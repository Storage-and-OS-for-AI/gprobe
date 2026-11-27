/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include "gprobe_shm.hpp"
#include "handler/map_handler.hpp"
#include "handler/memfd_handler.hpp"
#include <ebpf-vm.h>
#include "handler/epoll_handler.hpp"
#include "handler/handler_manager.hpp"
#include "handler/link_handler.hpp"
#include "handler/perf_event_handler.hpp"
#include "spdlog/spdlog.h"
#include <gprobe_shm_internal.hpp>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#if __linux__
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#ifdef GPROBE_ENABLE_CUDA_ATTACH
#include <cuda_runtime.h>
#include <cuda_runtime_api.h>
#include <cuda.h>
#endif
#if defined(GPROBE_ENABLE_CUDA_ATTACH) || defined(GPROBE_ENABLE_ROCM_ATTACH) || \
    defined(GPROBE_ENABLE_MACA_ATTACH)
#include <bpf_attach_ctx.hpp>
#endif
#ifdef GPROBE_ENABLE_CUDA_ATTACH
namespace gprobe
{
void stop_cuda_watcher_before_shm_unmap();
} // namespace gprobe
#endif
#ifdef GPROBE_ENABLE_ROCM_ATTACH
#include <hip/hip_runtime.h>
namespace gprobe
{
void stop_rocm_watcher_before_shm_unmap();
} // namespace gprobe
#endif
#ifdef GPROBE_ENABLE_MACA_ATTACH
#include <mc_runtime.h>
#include "maca_env_guard.hpp"
namespace gprobe
{
void stop_maca_watcher_before_shm_unmap();
} // namespace gprobe
#endif
#elif __APPLE__
#include "gprobe_epoll.h"
#endif
#include <unistd.h>
#include <variant>
#include <sys/mman.h>

static bool global_shm_initialized = false;

extern "C" void gprobe_initialize_global_shm(gprobe::shm_open_type type)
{
	using namespace gprobe;
	// Use placement new, which will not allocate memory, but just
	// call the constructor
	new (&shm_holder.global_shared_memory) gprobe_shm(type);
	global_shm_initialized = true;
	SPDLOG_INFO("Global shm initialized");
}

extern "C" void gprobe_destroy_global_shm()
{
	using namespace gprobe;
	if (global_shm_initialized) {
#ifdef GPROBE_ENABLE_CUDA_ATTACH
		stop_cuda_watcher_before_shm_unmap();
#endif
#ifdef GPROBE_ENABLE_ROCM_ATTACH
		stop_rocm_watcher_before_shm_unmap();
#endif
#ifdef GPROBE_ENABLE_MACA_ATTACH
		stop_maca_watcher_before_shm_unmap();
#endif
		// SPDLOG_INFO("Global shm destructed");
		shm_holder.global_shared_memory.~gprobe_shm();
		// Make this idempotent: clear the flag so a later explicit call
		// or the __destruct_shm static destructor does not destroy the
		// already-destroyed object a second time.
		global_shm_initialized = false;
		// Why not spdlog? because global variables that spdlog used
		// were already destroyed..
#ifdef DEBUG
		fprintf(stderr, "INFO [%d]: Global shm destructed\n",
			(int)getpid());
#endif
	}
}

extern "C" void gprobe_remove_global_shm()
{
	using namespace gprobe;
	if (boost::interprocess::shared_memory_object::remove(
		    get_global_shm_name()) != false) {
		SPDLOG_INFO("Global shm removed");
	}
}

static __attribute__((destructor(65535))) void __destruct_shm()
{
	// If the global shm was never successfully initialized (e.g. a process
	// that links the runtime but never created/opened shm, or whose
	// gprobe_shm constructor threw on the expected "shm not ready yet"
	// path), the object is uninitialized — touching it (get_open_type /
	// remove_pid_from_alive_agent_set) would read garbage and can crash on
	// exit. Bail out before any access.
	if (!global_shm_initialized)
		return;
	// This usually indicates that the living shared memory object is used
	// by an agent instance
	if (gprobe::shm_holder.global_shared_memory.get_open_type() ==
	    gprobe::shm_open_type::SHM_OPEN_ONLY) {
		// Try our best to remove the current pid from alive agent's set
		int self_pid = getpid();
		// It doesn't matter if the current pid is not in the set
		gprobe::shm_holder.global_shared_memory
			.remove_pid_from_alive_agent_set(self_pid);
	}

	gprobe_destroy_global_shm();
}

namespace gprobe
{

gprobe_shm_holder shm_holder;

namespace
{
class pid_set_scoped_lock {
public:
	explicit pid_set_scoped_lock(
		boost::interprocess::interprocess_mutex *mutex)
		: mutex(mutex)
	{
		if (mutex == nullptr) {
			locked = true;
			return;
		}

		const auto deadline = std::chrono::steady_clock::now() +
				      std::chrono::milliseconds(250);
		do {
			try {
				if (mutex->try_lock()) {
					locked = true;
					return;
				}
			} catch (const std::exception &ex) {
				SPDLOG_WARN(
					"Unable to lock gprobe pid set: {}",
					ex.what());
				return;
			} catch (...) {
				SPDLOG_WARN(
					"Unable to lock gprobe pid set");
				return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		} while (std::chrono::steady_clock::now() < deadline);

		SPDLOG_WARN("Timed out locking gprobe pid set");
	}

	pid_set_scoped_lock(const pid_set_scoped_lock &) = delete;
	pid_set_scoped_lock &
	operator=(const pid_set_scoped_lock &) = delete;

	~pid_set_scoped_lock()
	{
		if (locked && mutex != nullptr) {
			try {
				mutex->unlock();
			} catch (...) {
			}
		}
	}

	bool owns_lock() const noexcept { return locked; }

private:
	boost::interprocess::interprocess_mutex *mutex = nullptr;
	bool locked = false;
};
} // namespace

shm_lifecycle_lock::shm_lifecycle_lock(const char *shm_name) noexcept
{
#if __linux__
	try {
		std::string sanitized;
		for (const unsigned char ch :
		     std::string(shm_name == nullptr ? "" : shm_name)) {
			if (std::isalnum(ch) || ch == '_' || ch == '-' ||
			    ch == '.') {
				sanitized.push_back(static_cast<char>(ch));
			} else {
				sanitized.push_back('_');
			}
		}
		if (sanitized.empty()) {
			sanitized = "default";
		}
		std::string lock_path =
			"/tmp/gprobe-shm-" + sanitized + ".lock";
		lock_fd = open(lock_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC,
			       0666);
		if (lock_fd < 0) {
			return;
		}
		(void)fchmod(lock_fd, 0666);
		while (flock(lock_fd, LOCK_EX) != 0) {
			if (errno != EINTR) {
				close(lock_fd);
				lock_fd = -1;
				return;
			}
		}
	} catch (...) {
		if (lock_fd >= 0) {
			close(lock_fd);
			lock_fd = -1;
		}
	}
#else
	(void)shm_name;
#endif
}

shm_lifecycle_lock::~shm_lifecycle_lock()
{
#if __linux__
	if (lock_fd >= 0) {
		(void)flock(lock_fd, LOCK_UN);
		close(lock_fd);
	}
#endif
}

// Check whether a certain pid was already equipped with syscall tracer
// Using a set stored in the shared memory
bool gprobe_shm::check_syscall_trace_setup(int pid)
{
	if (syscall_installed_pids == nullptr) {
		return false;
	}
	pid_set_scoped_lock lock(pid_set_lock);
	if (!lock.owns_lock()) {
		return false;
	}
	return syscall_installed_pids->contains(pid);
}

// Set whether a certain pid was already equipped with syscall tracer
// Using a set stored in the shared memory
void gprobe_shm::set_syscall_trace_setup(int pid, bool whether)
{
	if (syscall_installed_pids == nullptr) {
		return;
	}
	auto update = [&]() {
		if (whether) {
			syscall_installed_pids->insert(pid);
		} else {
			syscall_installed_pids->erase(pid);
		}
	};
	pid_set_scoped_lock lock(pid_set_lock);
	if (!lock.owns_lock()) {
		return;
	}
	update();
}

const bpf_map_handler *gprobe_shm::try_get_map_handler(int fd) const
{
	if (!is_map_fd(fd)) {
		errno = ENOENT;
		return nullptr;
	}
	return &std::get<gprobe::bpf_map_handler>(manager->get_handler(fd));
}

uint32_t gprobe_shm::bpf_map_value_size(int fd) const
{
	auto *handler = try_get_map_handler(fd);
	return handler ? handler->get_userspace_value_size() : 0;
}

const void *gprobe_shm::bpf_map_lookup_elem(int fd, const void *key,
					     bool from_syscall) const
{
	auto *handler = try_get_map_handler(fd);
	return handler ? handler->map_lookup_elem(key, from_syscall) : nullptr;
}

long gprobe_shm::bpf_map_update_elem(int fd, const void *key,
				      const void *value, uint64_t flags,
				      bool from_syscall) const
{
	auto *handler = try_get_map_handler(fd);
	return handler ? handler->map_update_elem(key, value, flags,
						  from_syscall) :
			 -1;
}

long gprobe_shm::bpf_delete_elem(int fd, const void *key,
				  bool from_syscall) const
{
	auto *handler = try_get_map_handler(fd);
	return handler ? handler->map_delete_elem(key, from_syscall) : -1;
}

long gprobe_shm::bpf_map_push_elem(int fd, const void *value, uint64_t flags,
				    bool from_syscall) const
{
	auto *handler = try_get_map_handler(fd);
	return handler ? handler->map_push_elem(value, flags, from_syscall) : -1;
}

long gprobe_shm::bpf_map_pop_elem(int fd, void *value, bool from_syscall) const
{
	auto *handler = try_get_map_handler(fd);
	return handler ? handler->map_pop_elem(value, from_syscall) : -1;
}

long gprobe_shm::bpf_map_peek_elem(int fd, void *value,
				    bool from_syscall) const
{
	auto *handler = try_get_map_handler(fd);
	return handler ? handler->map_peek_elem(value, from_syscall) : -1;
}

int gprobe_shm::bpf_map_get_next_key(int fd, const void *key, void *next_key,
				      bool from_syscall) const
{
	auto *handler = try_get_map_handler(fd);
	return handler ?
		       handler->bpf_map_get_next_key(key, next_key,
						     from_syscall) :
		       -1;
}

int gprobe_shm::add_kprobe(std::optional<int> fd, const char *func_name,
			    uint64_t addr, bool retprobe, size_t ref_ctr_off)
{
	int new_fd = fd.has_value() ? *fd : open_fake_fd();
	SPDLOG_DEBUG(
		"Set fd {} to kprobe, func_name={},addr={:x},retprobe={},ref_ctr_off={}",
		new_fd, func_name, addr, retprobe, ref_ctr_off);

	return manager->set_handler(
		new_fd,
		gprobe::bpf_perf_event_handler(retprobe, addr, func_name,
						ref_ctr_off, segment),
		segment);
}
int gprobe_shm::add_uprobe(int fd, int pid, const char *name, uint64_t offset,
			    bool retprobe, size_t ref_ctr_off)
{
	if (fd < 0) {
		// if fd is negative, we need to create a new fd for allocating
		fd = open_fake_fd();
	}
	SPDLOG_DEBUG("Set fd {} to uprobe, pid={}, name={}, offset={}", fd, pid,
		     name, offset);
	return manager->set_handler(
		fd,
		gprobe::bpf_perf_event_handler{ retprobe, offset, pid, name,
						 ref_ctr_off, segment },
		segment);
}

int gprobe_shm::add_uprobe_override(int fd, int pid, const char *name,
				     uint64_t offset, bool is_replace)
{
	if (fd < 0) {
		// if fd is negative, we need to create a new fd for allocating
		fd = open_fake_fd();
	}
	SPDLOG_DEBUG("Set fd {} to ureplace, pid={}, name={}, offset={}", fd,
		     pid, name, offset);
	if (is_replace) {
		return manager->set_handler(
			fd,
			bpf_perf_event_handler(
				bpf_event_type::BPF_TYPE_UREPLACE, offset, pid,
				name, segment, true),
			segment);
	} else {
		return manager->set_handler(
			fd,
			bpf_perf_event_handler(
				bpf_event_type::BPF_TYPE_UPROBE_OVERRIDE,
				offset, pid, name, segment, true),
			segment);
	}
}

int gprobe_shm::add_tracepoint(int fd, int pid, int32_t tracepoint_id)
{
	if (fd < 0) {
		// if fd is negative, we need to create a new fd for allocating
		fd = open_fake_fd();
	}
	return manager->set_handler(
		fd,
		gprobe::bpf_perf_event_handler(pid, tracepoint_id, segment),
		segment);
}

int gprobe_shm::add_software_perf_event(int cpu, int32_t sample_type,
					 int64_t config)
{
	return add_software_perf_event(open_fake_fd(), cpu, sample_type,
				       config);
}

int gprobe_shm::add_software_perf_event(int fd, int cpu, int32_t sample_type,
					 int64_t config)
{
	return manager->set_handler(fd,
				    gprobe::bpf_perf_event_handler(
					    cpu, sample_type, config, segment),
				    segment);
}

int gprobe_shm::attach_perf_to_bpf(int perf_fd, int bpf_fd,
				    std::optional<uint64_t> cookie)
{
	if (!is_perf_fd(perf_fd)) {
		SPDLOG_ERROR("Fd {} is not a perf fd", perf_fd);
		errno = ENOENT;
		return -1;
	}
	return add_bpf_prog_attach_target(perf_fd, bpf_fd, cookie);
}

int gprobe_shm::add_bpf_prog_attach_target(int perf_fd, int bpf_fd,
					    std::optional<uint64_t> cookie)
{
	SPDLOG_DEBUG("Try attaching prog fd {} to perf fd {}, with cookie = {}",
		     bpf_fd, perf_fd, cookie.has_value());
	if (cookie) {
		SPDLOG_DEBUG("With cookie: {}", *cookie);
	}

	if (!is_prog_fd(bpf_fd)) {
		SPDLOG_ERROR("Fd {} is not a prog fd", bpf_fd);
		errno = ENOENT;
		return -1;
	}
	int next_id = open_fake_fd();
	if (next_id < 0) {
		SPDLOG_ERROR("Unable to find an available id: {}", next_id);
		return -ENOSPC;
	}
	manager->set_handler(next_id, bpf_link_handler(bpf_fd, perf_fd, cookie),
			     segment);
	return next_id;
}

int gprobe_shm::perf_event_enable(int fd) const
{
	if (!is_perf_fd(fd)) {
		errno = ENOENT;
		return -1;
	}
	auto &handler = std::get<gprobe::bpf_perf_event_handler>(
		manager->get_handler(fd));
	return handler.enable();
}

int gprobe_shm::perf_event_disable(int fd) const
{
	if (!is_perf_fd(fd)) {
		errno = ENOENT;
		return -1;
	}
	auto &handler = std::get<gprobe::bpf_perf_event_handler>(
		manager->get_handler(fd));
	return handler.disable();
}

int gprobe_shm::add_software_perf_event_to_epoll(int swpe_fd, int epoll_fd,
						  epoll_data_t extra_data)
{
	if (!is_epoll_fd(epoll_fd)) {
		SPDLOG_ERROR("Fd {} is expected to be an epoll fd", epoll_fd);
		errno = EINVAL;
		return -1;
	}
	auto &epoll_inst =
		std::get<epoll_handler>(manager->get_handler(epoll_fd));
	if (!is_software_perf_event_handler_fd(swpe_fd)) {
		SPDLOG_ERROR(
			"Fd {} is expected to be an software perf event handler",
			swpe_fd);
		errno = EINVAL;
		return -1;
	}
	auto &perf_handler =
		std::get<bpf_perf_event_handler>(manager->get_handler(swpe_fd));
	if (perf_handler.type != (int)bpf_event_type::PERF_TYPE_SOFTWARE) {
		SPDLOG_ERROR(
			"Expected perf fd {} to be a software perf event instance",
			swpe_fd);
		errno = EINVAL;
		return -1;
	}
	if (auto ptr = perf_handler.try_get_software_perf_data_weak_ptr();
	    ptr.has_value()) {
		epoll_inst.files.emplace_back(ptr.value(), extra_data);
		return 0;
	} else {
		SPDLOG_ERROR(
			"Expected perf handler {} to have software perf event data",
			swpe_fd);
		errno = EINVAL;
		return -1;
	}
}
int gprobe_shm::add_ringbuf_to_epoll(int ringbuf_fd, int epoll_fd,
				      epoll_data_t extra_data)
{
	if (!is_epoll_fd(epoll_fd)) {
		SPDLOG_ERROR("Fd {} is expected to be an epoll fd", epoll_fd);
		errno = EINVAL;
		return -1;
	}
	auto &epoll_inst =
		std::get<epoll_handler>(manager->get_handler(epoll_fd));

	if (!is_map_fd(ringbuf_fd)) {
		SPDLOG_ERROR("Fd {} is expected to be an map fd", ringbuf_fd);
		errno = EINVAL;
		return -1;
	}
	auto &map_inst =
		std::get<bpf_map_handler>(manager->get_handler(ringbuf_fd));

	auto ringbuf_map_impl = map_inst.try_get_ringbuf_map_impl();
	if (auto val = ringbuf_map_impl.value_or(nullptr)) {
		epoll_inst.files.emplace_back(val->create_impl_weak_ptr(),
					      extra_data);
		SPDLOG_DEBUG("Ringbuf {} added to epoll {}", ringbuf_fd,
			     epoll_fd);
		return 0;
	} else {
		errno = EINVAL;
		SPDLOG_ERROR("Map fd {} is expected to be an ringbuf map",
			     ringbuf_fd);
		return -1;
	}
}
int gprobe_shm::epoll_create()
{
	int fd = open_fake_fd();
	if (manager->is_allocated(fd)) {
		SPDLOG_ERROR(
			"Creating epoll instance, but fd {} is already occupied",
			fd);
		return -1;
	}
	fd = manager->set_handler(fd, gprobe::epoll_handler(segment), segment);
	SPDLOG_DEBUG("Epoll instance created: fd={}", fd);
	return fd;
}

const handler_variant &gprobe_shm::get_handler(int fd) const
{
	return manager->get_handler(fd);
}
bool gprobe_shm::is_epoll_fd(int fd) const
{
	if (manager == nullptr || fd < 0 ||
	    (std::size_t)fd >= manager->size()) {
		SPDLOG_ERROR("Invalid fd: {}", fd);
		return false;
	}
	const auto &handler = manager->get_handler(fd);
	return std::holds_alternative<gprobe::epoll_handler>(handler);
}

bool gprobe_shm::is_stack_trace_map_fd(int fd) const
{
	if (!is_map_fd(fd))
		return false;
	auto &map_impl = std::get<bpf_map_handler>(manager->get_handler(fd));
	return map_impl.type == bpf_map_type::BPF_MAP_TYPE_STACK_TRACE;
}
std::optional<stack_trace_map_impl *>
gprobe_shm::try_get_stack_trace_impl(int fd) const
{
	if (!is_stack_trace_map_fd(fd)) {
		SPDLOG_ERROR("Expected fd {} to be an stack trace map fd", fd);
		return {};
	}
	auto &map_handler = std::get<bpf_map_handler>(manager->get_handler(fd));
	return map_handler.try_get_stack_trace_map_impl();
}

bool gprobe_shm::is_map_fd(int fd) const
{
	if (manager == nullptr || fd < 0 ||
	    (std::size_t)fd >= manager->size()) {
		return false;
	}
	const auto &handler = manager->get_handler(fd);
	return std::holds_alternative<gprobe::bpf_map_handler>(handler);
}
bool gprobe_shm::is_ringbuf_map_fd(int fd) const
{
	if (!is_map_fd(fd))
		return false;
	auto &map_impl = std::get<bpf_map_handler>(manager->get_handler(fd));
	return map_impl.type == bpf_map_type::BPF_MAP_TYPE_RINGBUF;
}
bool gprobe_shm::is_shared_perf_event_array_map_fd(int fd) const
{
	if (!is_map_fd(fd))
		return false;
	auto &map_impl = std::get<bpf_map_handler>(manager->get_handler(fd));
	return map_impl.type ==
	       bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY;
}
bool gprobe_shm::is_array_map_fd(int fd) const
{
	if (!is_map_fd(fd))
		return false;
	auto &map_impl = std::get<bpf_map_handler>(manager->get_handler(fd));
	return map_impl.type == bpf_map_type::BPF_MAP_TYPE_ARRAY;
}

bool gprobe_shm::is_prog_array_map_fd(int fd) const
{
	if (!is_map_fd(fd))
		return false;
	auto &map_impl = std::get<bpf_map_handler>(manager->get_handler(fd));
	return map_impl.type == bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY;
}
std::optional<ringbuf_map_impl *>
gprobe_shm::try_get_ringbuf_map_impl(int fd) const
{
	if (!is_ringbuf_map_fd(fd)) {
		SPDLOG_ERROR("Expected fd {} to be an ringbuf map fd", fd);
		return {};
	}
	auto &map_handler = std::get<bpf_map_handler>(manager->get_handler(fd));
	return map_handler.try_get_ringbuf_map_impl();
}

std::optional<array_map_impl *>
gprobe_shm::try_get_array_map_impl(int fd) const
{
	if (!is_array_map_fd(fd)) {
		SPDLOG_ERROR("Expected fd {} to be an array map fd", fd);
		return {};
	}
	auto &map_handler = std::get<bpf_map_handler>(manager->get_handler(fd));
	return map_handler.try_get_array_map_impl();
}
bool gprobe_shm::is_prog_fd(int fd) const
{
	if (manager == nullptr || fd < 0 ||
	    (std::size_t)fd >= manager->size()) {
		return false;
	}
	const auto &handler = manager->get_handler(fd);
	return std::holds_alternative<gprobe::bpf_prog_handler>(handler);
}

bool gprobe_shm::is_perf_fd(int fd) const
{
	if (manager == nullptr || fd < 0 ||
	    (std::size_t)fd >= manager->size()) {
		return false;
	}
	const auto &handler = manager->get_handler(fd);
	return std::holds_alternative<gprobe::bpf_perf_event_handler>(handler);
}

int gprobe_shm::open_fake_fd()
{
	int fd = open("/dev/null", O_RDONLY);
	int cnt = 5;
	while (fd <= 2 && fd >= 0 && --cnt > 0) {
		fd = dup(fd);
	}
	if (fd >= 0 && (std::size_t)fd >= manager->size()) {
		SPDLOG_ERROR("open_fake_fd: fd {} exceeds handler pool size {}", fd, manager->size());
		close(fd);
		errno = ENOSPC;
		return -1;
	}
	return fd;
}

// handle bpf commands to load a bpf program
int gprobe_shm::add_bpf_prog(int fd, const ebpf_inst *insn, size_t insn_cnt,
			      const char *prog_name, int prog_type)
{
	if (fd < 0) {
		// if fd is negative, we need to create a new fd for allocating
		fd = open_fake_fd();
	}
	SPDLOG_DEBUG(
		"Set handler fd {} to bpf_prog_handler, name {}, prog_type {}, insn_cnt {}",
		fd, prog_name, prog_type, insn_cnt);
	return manager->set_handler(
		fd,
		gprobe::bpf_prog_handler(segment, insn, insn_cnt, prog_name,
					  prog_type),
		segment);
}

// add a bpf link fd
int gprobe_shm::add_bpf_link(int fd, struct bpf_link_create_args *args)
{
	if (!args) {
		errno = EINVAL;
		return -1;
	}
	// Validate before allocating an fd so error paths don't leak the fd that
	// open_fake_fd() would otherwise create.
	if (!is_prog_fd(args->prog_fd)) {
		errno = EBADF;
		return -1;
	}
	// For perf-event links (uprobe/kprobe/tracepoint) the target must be a
	// valid perf-event handler fd, matching the kernel's BPF_LINK_CREATE
	// validation. Without this a stale/non-perf target_fd would be silently
	// accepted.
	if (args->attach_type == GPROBE_BPF_PERF_EVENT_ATTACH_TYPE &&
	    !is_perf_event_handler_fd(args->target_fd)) {
		int target_fd_for_log =
			args->target_fd == static_cast<uint32_t>(-1) ?
				-1 :
				static_cast<int>(args->target_fd);
		// libbpf probes perf-link support with target_fd=-1 and expects
		// EBADF, so don't report that expected probe as an error.
		if (args->target_fd == static_cast<uint32_t>(-1)) {
			SPDLOG_DEBUG(
				"add_bpf_link: rejecting expected libbpf perf-link probe with target_fd -1");
		} else {
			SPDLOG_ERROR(
				"add_bpf_link: target_fd {} is not a perf-event handler for BPF_PERF_EVENT link",
				target_fd_for_log);
		}
		errno = EBADF;
		return -1;
	}
	if (fd < 0) {
		// if fd is negative, we need to create a new fd for allocating
		fd = open_fake_fd();
	}
	return manager->set_handler(fd, gprobe::bpf_link_handler(*args),
				    segment);
}

void gprobe_shm::close_fd(int fd)
{
	if (manager) {
		manager->clear_id_at(fd, segment);
	}
}

#if GPROBE_ENABLE_MPK
void gprobe_shm::enable_mpk()
{
	if (manager == nullptr || !is_mpk_init) {
		return;
	}
	if (pkey_set(pkey, PKEY_DISABLE_WRITE) == -1) {
		SPDLOG_ERROR("pkey_set read only failed");
	}
}

void gprobe_shm::disable_mpk()
{
	if (manager == nullptr || !is_mpk_init) {
		return;
	}
	if (pkey_set(pkey, 0) == -1) {
		SPDLOG_ERROR("pkey_set disable failed");
	}
}
#endif

bool gprobe_shm::is_exist_fake_fd(int fd) const
{
	if (manager == nullptr || fd < 0 ||
	    (std::size_t)fd >= manager->size()) {
		return false;
	}
	return manager->is_allocated(fd);
}

gprobe_shm::gprobe_shm(const char *shm_name, shm_open_type type)
	: open_type(type)
{
	// Get the config from env because the shared memory is not initialized
	auto config = construct_runtime_config_from_env();
	size_t memory_size = config.shm_memory_size;
	size_t max_fd_count = config.max_fd_count;
	if (type == shm_open_type::SHM_OPEN_ONLY) {
		SPDLOG_DEBUG("start: gprobe_shm for client setup");
		// open the shm
		segment = boost::interprocess::managed_shared_memory(
			boost::interprocess::open_only, shm_name);
		manager = segment.find<gprobe::handler_manager>(
					 gprobe::DEFAULT_GLOBAL_HANDLER_NAME)
				  .first;
		syscall_installed_pids =
			segment.find<syscall_pid_set>(
				       DEFAULT_SYSCALL_PID_SET_NAME)
				.first;
		runtime_config =
			segment.find<struct runtime_config>(
				       gprobe::DEFAULT_AGENT_CONFIG_NAME)
				.first;

		injected_pids =
			segment.find<alive_agent_pids>(
				       gprobe::DEFAULT_ALIVE_AGENT_PIDS_NAME)
				.first;
		alive_syscall_server_pids =
			segment.find<alive_syscall_server_pid_set>(
				       gprobe::DEFAULT_ALIVE_SYSCALL_SERVER_PIDS_NAME)
				.first;
		pid_set_lock =
			segment.find<boost::interprocess::interprocess_mutex>(
				       gprobe::DEFAULT_PID_SET_LOCK_NAME)
				.first;
		epoch_state = segment.find<gprobe_global_epoch_state>(
					     "gprobe_global_epoch_state")
				      .first;
		SPDLOG_DEBUG("done: gprobe_shm for client setup");
	} else if (type == shm_open_type::SHM_CREATE_OR_OPEN ||
		   type == shm_open_type::SHM_CREATE_ONLY) {
		SPDLOG_DEBUG(
			"start: gprobe_shm for create or open setup for memory size {}",
			memory_size);
		if (type == shm_open_type::SHM_CREATE_ONLY) {
			segment = boost::interprocess::managed_shared_memory(
				boost::interprocess::create_only, shm_name,
				memory_size << 20);
		} else {
			segment = boost::interprocess::managed_shared_memory(
				boost::interprocess::open_or_create, shm_name,
				memory_size << 20);
		}

		manager = segment.find_or_construct<gprobe::handler_manager>(
			gprobe::DEFAULT_GLOBAL_HANDLER_NAME)(segment,
							      max_fd_count);
		SPDLOG_DEBUG("done: gprobe_shm for server setup: manager");

		syscall_installed_pids =
			segment.find_or_construct<syscall_pid_set>(
				gprobe::DEFAULT_SYSCALL_PID_SET_NAME)(
				std::less<int>(),
				syscall_pid_set_allocator(
					segment.get_segment_manager()));
		SPDLOG_DEBUG(
			"done: gprobe_shm for server setup: syscall_pid_set");

		runtime_config = segment.find_or_construct<struct runtime_config>(
			gprobe::DEFAULT_AGENT_CONFIG_NAME)(config);

		injected_pids = segment.find_or_construct<alive_agent_pids>(
			gprobe::DEFAULT_ALIVE_AGENT_PIDS_NAME)(
			std::less<int>(),
			alive_agent_pid_set_allocator(
				segment.get_segment_manager()));
		alive_syscall_server_pids =
			segment.find_or_construct<alive_syscall_server_pid_set>(
				gprobe::DEFAULT_ALIVE_SYSCALL_SERVER_PIDS_NAME)(
				std::less<int>(),
				alive_syscall_server_pid_set_allocator(
					segment.get_segment_manager()));
		pid_set_lock =
			segment.find_or_construct<
				boost::interprocess::interprocess_mutex>(
				gprobe::DEFAULT_PID_SET_LOCK_NAME)();
		epoch_state =
			segment.find_or_construct<gprobe_global_epoch_state>(
				"gprobe_global_epoch_state")();
		SPDLOG_DEBUG("done: gprobe_shm for open_or_create setup");
	} else if (type == shm_open_type::SHM_REMOVE_AND_CREATE) {
		SPDLOG_DEBUG(
			"start: gprobe_shm for server setup for memory size {}",
			memory_size);
		boost::interprocess::shared_memory_object::remove(shm_name);
		// create the shm
		SPDLOG_DEBUG(
			"done: gprobe_shm for server setup: remove installed segment");
		segment = boost::interprocess::managed_shared_memory(
			boost::interprocess::create_only,
			// Allocate 20M bytes of memory by default
			shm_name, memory_size << 20);
		SPDLOG_DEBUG("done: gprobe_shm for server setup: segment");

		manager = segment.construct<gprobe::handler_manager>(
			gprobe::DEFAULT_GLOBAL_HANDLER_NAME)(segment,
							      max_fd_count);
		SPDLOG_DEBUG("done: gprobe_shm for server setup: manager");

		syscall_installed_pids = segment.construct<syscall_pid_set>(
			gprobe::DEFAULT_SYSCALL_PID_SET_NAME)(
			std::less<int>(),
			syscall_pid_set_allocator(
				segment.get_segment_manager()));
		SPDLOG_DEBUG(
			"done: gprobe_shm for server setup: syscall_pid_set");

		runtime_config = segment.construct<struct runtime_config>(
			gprobe::DEFAULT_AGENT_CONFIG_NAME)(config);
		SPDLOG_DEBUG(
			"done: gprobe_shm for server setup: runtime_config");

		injected_pids = segment.construct<alive_agent_pids>(
			gprobe::DEFAULT_ALIVE_AGENT_PIDS_NAME)(
			std::less<int>(),
			alive_agent_pid_set_allocator(
				segment.get_segment_manager()));
		alive_syscall_server_pids =
			segment.construct<alive_syscall_server_pid_set>(
				gprobe::DEFAULT_ALIVE_SYSCALL_SERVER_PIDS_NAME)(
				std::less<int>(),
				alive_syscall_server_pid_set_allocator(
					segment.get_segment_manager()));
		pid_set_lock =
			segment.construct<
				boost::interprocess::interprocess_mutex>(
				gprobe::DEFAULT_PID_SET_LOCK_NAME)();
		epoch_state = segment.construct<gprobe_global_epoch_state>(
			"gprobe_global_epoch_state")();
		SPDLOG_DEBUG("done: gprobe_shm for server setup.");
	} else if (type == shm_open_type::SHM_NO_CREATE) {
		// not create any shm
		SPDLOG_WARN(
			"NOT creating global shm. This is only for testing purpose.");
		return;
	}
#ifdef GPROBE_ENABLE_CUDA_ATTACH
	// Move CommSharedMem from the agent’s local memory to shared memory to
	// improve performance.
	if (open_type == shm_open_type::SHM_OPEN_ONLY) {
		auto pair = segment.find<cuda::CommSharedMem>(
			"cuda_comm_shared_mem");
		for (int i = 0; pair.first == nullptr && i < 100; i++) {
			usleep(10000);
			pair = segment.find<cuda::CommSharedMem>(
				"cuda_comm_shared_mem");
		}
		if (pair.first == nullptr) {
			SPDLOG_ERROR(
				"CommSharedMem not found in shared memory; did syscall-server initialize CUDA support?");
			cuda_comm_shared_mem = nullptr;
		} else {
			cuda_comm_shared_mem = pair.first;
		}
		// Register the shared communication memory for CUDA device
		// mapping. This must happen after we have located the
		// CommSharedMem in the shared segment.
		if (cuda_comm_shared_mem != nullptr)
			register_cuda_host_memory();
	} else {
		auto pair = segment.find<cuda::CommSharedMem>(
			"cuda_comm_shared_mem");
		if (pair.first != nullptr) {
			cuda_comm_shared_mem = pair.first;
		} else {
			cuda_comm_shared_mem =
				segment.construct<cuda::CommSharedMem>(
					"cuda_comm_shared_mem")();
			memset(cuda_comm_shared_mem, 0,
			       sizeof(cuda::CommSharedMem));
			SPDLOG_DEBUG(
				"Constructed CommSharedMem in shared memory at {:p}",
				(void *)cuda_comm_shared_mem);
		}
	}
#endif
#ifdef GPROBE_ENABLE_ROCM_ATTACH
	if (open_type == shm_open_type::SHM_OPEN_ONLY) {
		auto pair = segment.find<rocm::CommSharedMem>(
			"rocm_comm_shared_mem");
		for (int i = 0; pair.first == nullptr && i < 100; i++) {
			usleep(10000);
			pair = segment.find<rocm::CommSharedMem>(
				"rocm_comm_shared_mem");
		}
		if (pair.first == nullptr) {
			SPDLOG_ERROR(
				"ROCM CommSharedMem not found in shared memory");
			rocm_comm_shared_mem = nullptr;
		} else {
			rocm_comm_shared_mem = pair.first;
		}
		// Register the whole shared memory segment for ROCM device
		// mapping. This must happen after we have located the
		// CommSharedMem in the shared segment.
		if (rocm_comm_shared_mem != nullptr)
			register_rocm_host_memory();
	} else {
		auto pair = segment.find<rocm::CommSharedMem>(
			"rocm_comm_shared_mem");
		if (pair.first != nullptr) {
			rocm_comm_shared_mem = pair.first;
		} else {
			rocm_comm_shared_mem =
				segment.construct<rocm::CommSharedMem>(
					"rocm_comm_shared_mem")();
			memset(rocm_comm_shared_mem, 0,
			       sizeof(rocm::CommSharedMem));
			SPDLOG_DEBUG(
				"Constructed ROCM CommSharedMem at {:p}",
				(void *)rocm_comm_shared_mem);
		}
	}
#endif
#ifdef GPROBE_ENABLE_MACA_ATTACH
	if (open_type == shm_open_type::SHM_OPEN_ONLY) {
		auto pair = segment.find<maca::CommSharedMem>(
			"maca_comm_shared_mem");
		for (int i = 0; pair.first == nullptr && i < 100; i++) {
			usleep(10000);
			pair = segment.find<maca::CommSharedMem>(
				"maca_comm_shared_mem");
		}
		if (pair.first == nullptr) {
			SPDLOG_ERROR(
				"MACA CommSharedMem not found in shared memory");
			maca_comm_shared_mem = nullptr;
		} else {
			maca_comm_shared_mem = pair.first;
		}
		// Register the whole shared memory segment for MACA device
		// mapping. This must happen after we have located the
		// CommSharedMem in the shared segment.
		if (maca_comm_shared_mem != nullptr)
			register_maca_host_memory();
	} else {
		auto pair = segment.find<maca::CommSharedMem>(
			"maca_comm_shared_mem");
		if (pair.first != nullptr) {
			maca_comm_shared_mem = pair.first;
		} else {
			maca_comm_shared_mem =
				segment.construct<maca::CommSharedMem>(
					"maca_comm_shared_mem")();
			memset(maca_comm_shared_mem, 0,
			       sizeof(maca::CommSharedMem));
			SPDLOG_DEBUG(
				"Constructed MACA CommSharedMem at {:p}",
				(void *)maca_comm_shared_mem);
		}
	}
#endif
	// local_runtime_config.emplace(segment);

#if GPROBE_ENABLE_MPK
	// init mpk key
	pkey = pkey_alloc(0, PKEY_DISABLE_WRITE);
	if (pkey == -1) {
		SPDLOG_ERROR("pkey_alloc failed");
		return;
	}

	// protect shm segment
	if (pkey_mprotect(segment.get_address(), segment.get_size(),
			  PROT_READ | PROT_WRITE, pkey) == -1) {
		SPDLOG_ERROR("pkey_mprotect failed");
		return;
	}
	is_mpk_init = true;
#endif
}

std::uint64_t gprobe_shm::read_stable_epoch_seq(int max_tries) const
{
	if (!epoch_state)
		return GPROBE_EPOCH_SEQ_MISSING;
	for (int i = 0; i < max_tries; i++) {
		std::uint64_t a = __atomic_load_n(&epoch_state->epoch_seq,
						  __ATOMIC_ACQUIRE);
		if (a & 1U) {
			// Writer in progress.
			usleep(1000);
			continue;
		}
		std::uint64_t b = __atomic_load_n(&epoch_state->epoch_seq,
						  __ATOMIC_ACQUIRE);
		if (a == b)
			return a;
	}
	return GPROBE_EPOCH_SEQ_UNSTABLE;
}

std::uint64_t gprobe_shm::begin_new_session()
{
	if (!epoch_state) {
		SPDLOG_WARN("begin_new_session: epoch_state missing");
		reset_server_state();
		return 0;
	}
	// Mark updating (odd).
	__atomic_add_fetch(&epoch_state->epoch_seq, 1, __ATOMIC_ACQ_REL);
	reset_server_state();
	// Mark stable (even).
	std::uint64_t seq = __atomic_add_fetch(&epoch_state->epoch_seq, 1,
					       __ATOMIC_ACQ_REL);
	return seq;
}

gprobe_shm::gprobe_shm(gprobe::shm_open_type type)
	: gprobe_shm(gprobe::get_global_shm_name(), type)
{
	SPDLOG_INFO("Global shm constructed. shm_open_type {} for {}",
		    (int)type, gprobe::get_global_shm_name());
}
int gprobe_shm::translate_shared_map_type_to_kernel_map_type(int type)
{
	if (type ==
	    (int)bpf_map_type::BPF_MAP_TYPE_GPU_KERNEL_SHARED_ARRAY_MAP) {
		return (int)bpf_map_type::BPF_MAP_TYPE_ARRAY;
	} else {
		return type;
	}
}
int gprobe_shm::add_bpf_map(int fd, const char *name,
			     gprobe::bpf_map_attr attr)
{
	if (fd < 0) {
		// if fd is negative, we need to create a new fd for allocating
		fd = open_fake_fd();
	}
	if (!manager) {
		return -1;
	}
#ifdef ENABLE_GPROBE_VERIFIER
	auto helpers = verifier::get_map_descriptors();
	helpers[fd] = verifier::GprobeMapDescriptor{
		.original_fd = fd,
		.type = static_cast<uint32_t>(attr.type),
		.key_size = attr.key_size,
		.value_size = attr.value_size,
		.max_entries = attr.max_ents,
		.inner_map_fd = static_cast<unsigned int>(-1)
	};
	verifier::set_map_descriptors(helpers);
#endif
	if (!std::holds_alternative<unused_handler>(manager->get_handler(fd))) {
		SPDLOG_DEBUG(
			"Creating map handler at {}, which must destroy the existing handler");
		manager->clear_id_at(fd, segment);
	}
	return manager->set_handler(
		fd, gprobe::bpf_map_handler(fd, name, segment, attr), segment);
}

int gprobe_shm::dup_bpf_map(int oldfd, int newfd)
{
	if (!is_map_fd(oldfd)) {
		SPDLOG_ERROR("Expected {} to be a map fd", oldfd);
		errno = EBADF;
		return -1;
	}
	if (newfd < 0) {
		// if fd is negative, we need to create a new fd for allocating
		newfd = open_fake_fd();
	}
	if (!manager) {
		return -1;
	}

	// Get the original map handler
	auto &handler =
		std::get<gprobe::bpf_map_handler>(manager->get_handler(oldfd));
	// A dup(2)'d fd should reference the same underlying map. Keep the same
	// map name when possible so we can share the same container in shm.
	std::string shared_name = handler.name.c_str();
	std::string fallback_name = std::string("dup_") + handler.name.c_str();
	// Destroy old handler
	auto &old_handler = manager->get_handler(newfd);
	if (!std::holds_alternative<unused_handler>(old_handler)) {
		SPDLOG_DEBUG("Dup to fd {}, destroying old handler", newfd);

		manager->clear_id_at(newfd, segment);
	}

	if (handler.can_share_map_impl()) {
		gprobe::bpf_map_handler dup_handler(newfd, shared_name.c_str(),
						     segment, handler.attr);
		dup_handler.share_map_impl_from(handler);
		handler.inc_map_refcount();
		return manager->set_handler(newfd, std::move(dup_handler),
					    segment);
	}

	// Fallback: create an independent map if the source map doesn't support
	// sharing (e.g. legacy shm objects).
	return manager->set_handler(
		newfd,
		gprobe::bpf_map_handler(newfd, fallback_name.c_str(), segment,
					 handler.attr),
		segment);
}

const handler_manager *gprobe_shm::get_manager() const
{
	return manager;
}

bool gprobe_shm::is_perf_event_handler_fd(int fd) const
{
	if (manager == nullptr || fd < 0 ||
	    (std::size_t)fd >= manager->size()) {
		return false;
	}
	auto &handler = get_handler(fd);
	return std::holds_alternative<bpf_perf_event_handler>(handler);
}

bool gprobe_shm::is_software_perf_event_handler_fd(int fd) const
{
	if (!is_perf_event_handler_fd(fd))
		return false;
	const auto &hd = std::get<bpf_perf_event_handler>(get_handler(fd));
	return hd.type == (int)bpf_event_type::PERF_TYPE_SOFTWARE;
}

// local agent config can be used for test or local process

void gprobe_shm::set_runtime_config(struct runtime_config &&config)
{
	if (runtime_config == nullptr) {
		SPDLOG_INFO(
			"global runtime_config is nullptr, set current process config");
		local_runtime_config.emplace(std::move(config));
		return;
	}

	runtime_config->~runtime_config();
	std::construct_at(runtime_config, std::move(config));
}

const struct runtime_config &gprobe_shm::get_runtime_config()
{
	if (runtime_config == nullptr) {
		SPDLOG_DEBUG("use current process config");
		return *local_runtime_config;
	}
	return *runtime_config;
}

const gprobe::runtime_config &gprobe_get_runtime_config()
{
	return shm_holder.global_shared_memory.get_runtime_config();
}

void gprobe_set_runtime_config(gprobe::runtime_config &&cfg)
{
	shm_holder.global_shared_memory.set_runtime_config(std::move(cfg));
}

std::optional<void *>
gprobe_shm::get_software_perf_event_raw_buffer(int fd, size_t buffer_sz) const
{
	if (!is_software_perf_event_handler_fd(fd)) {
		SPDLOG_ERROR("Expected {} to be an perf event fd", fd);
		errno = EINVAL;
		return nullptr;
	}
	const auto &handler = std::get<bpf_perf_event_handler>(get_handler(fd));
	return handler.try_get_software_perf_data_raw_buffer(buffer_sz);
}
int gprobe_shm::add_custom_perf_event(int type, const char *attach_argument)
{
	int fd = open_fake_fd();
	if (fd < 0) {
		SPDLOG_ERROR("Unable to allocate id for custom perf event: {}",
			     errno);
		return fd;
	}
	manager->set_handler(
		fd, bpf_perf_event_handler(type, attach_argument, segment),
		segment);
	return fd;
}
#ifdef GPROBE_ENABLE_CUDA_ATTACH
bool gprobe_shm::register_cuda_host_memory()
{
	if (open_type != shm_open_type::SHM_OPEN_ONLY) {
		SPDLOG_WARN("Only agent side can register cuda host memory");
		return false;
	}

	const auto prefault_range = [](void *addr, std::size_t size) {
		constexpr std::size_t kPageSize = 4096;
		volatile unsigned char sink = 0;
		auto *p = static_cast<volatile unsigned char *>(addr);
		for (std::size_t i = 0; i < size; i += kPageSize) {
			sink ^= p[i];
		}
	};

	// Ensure we can map host memory into device address space
	cudaError_t flag_err = cudaSetDeviceFlags(cudaDeviceMapHost);
	if (flag_err != cudaSuccess &&
	    flag_err != cudaErrorSetOnActiveProcess) {
		SPDLOG_WARN("cudaSetDeviceFlags(cudaDeviceMapHost) failed: {}",
			    cudaGetErrorString(flag_err));
	}
	if (flag_err == cudaErrorSetOnActiveProcess) {
		// Clear the sticky error
		cudaGetLastError();
	}

	// 1. Get the base address and size of the Boost.Interprocess segment
	void *base_addr = segment.get_address(); // Starting address
	std::size_t seg_size = segment.get_size(); // Total bytes in segment
	prefault_range(base_addr, seg_size);

	// 2. Register with CUDA
	cudaError_t err =
		cudaHostRegister(base_addr, seg_size, cudaHostRegisterMapped);
	if (err != cudaSuccess) {
		SPDLOG_ERROR("cudaHostRegister() failed: {}",
			     cudaGetErrorString(err));
		return false;
	}

	SPDLOG_INFO("Registered shared memory with CUDA: addr={} size={}",
		    base_addr, seg_size);
	cuda_host_memory_registered = true;
	return true;
}
#endif
#ifdef GPROBE_ENABLE_ROCM_ATTACH
bool gprobe_shm::register_rocm_host_memory()
{
	if (open_type != shm_open_type::SHM_OPEN_ONLY) {
		SPDLOG_WARN("Only agent side can register rocm host memory");
		return false;
	}

	const auto prefault_range = [](void *addr, std::size_t size) {
		constexpr std::size_t kPageSize = 4096;
		volatile unsigned char sink = 0;
		auto *p = static_cast<volatile unsigned char *>(addr);
		for (std::size_t i = 0; i < size; i += kPageSize) {
			sink ^= p[i];
		}
	};

	// Make sure the HIP runtime is up: the ROCmContext is created later,
	// so this registration may be the first HIP call in the process.
	hipError_t init_err = hipInit(0);
	if (init_err != hipSuccess) {
		SPDLOG_ERROR("hipInit failed: {}",
			     hipGetErrorString(init_err));
		return false;
	}

	// 1. Get the base address and size of the Boost.Interprocess segment
	void *base_addr = segment.get_address(); // Starting address
	std::size_t seg_size = segment.get_size(); // Total bytes in segment
	prefault_range(base_addr, seg_size);

	// 2. Register with HIP so the whole segment becomes GPU-accessible
	// (mirrors the CUDA side, which registers the whole segment with
	// cudaHostRegisterMapped)
	hipError_t err = hipHostRegister(base_addr, seg_size,
					 hipHostRegisterDefault);
	if (err != hipSuccess) {
		SPDLOG_ERROR("hipHostRegister() failed: {}",
			     hipGetErrorString(err));
		return false;
	}

	SPDLOG_INFO("Registered shared memory with ROCM: addr={} size={}",
		    base_addr, seg_size);
	rocm_host_memory_registered = true;
	return true;
}
#endif
#ifdef GPROBE_ENABLE_MACA_ATTACH
bool gprobe_shm::register_maca_host_memory()
{
	if (open_type != shm_open_type::SHM_OPEN_ONLY) {
		SPDLOG_WARN("Only agent side can register maca host memory");
		return false;
	}

	const auto prefault_range = [](void *addr, std::size_t size) {
		constexpr std::size_t kPageSize = 4096;
		volatile unsigned char sink = 0;
		auto *p = static_cast<volatile unsigned char *>(addr);
		for (std::size_t i = 0; i < size; i += kPageSize) {
			sink ^= p[i];
		}
	};

	// Make sure the MACA runtime is up: the MACAContext is created later,
	// so this registration may be the first MACA call in the process.
	// The env guard hides LD_PRELOAD from mcInit's internal zip probe
	// child (it would re-run this library's constructor and deadlock on
	// the shm flock we may be holding).
	maca::maca_runtime_env_guard env_guard;
	mcError_t init_err = mcInit(0);
	if (init_err != mcSuccess) {
		SPDLOG_ERROR("mcInit failed: {}",
			     mcGetErrorString(init_err));
		return false;
	}

	// 1. Get the base address and size of the Boost.Interprocess segment
	void *base_addr = segment.get_address(); // Starting address
	std::size_t seg_size = segment.get_size(); // Total bytes in segment
	prefault_range(base_addr, seg_size);

	// 2. Register with MACA so the whole segment becomes GPU-accessible
	// (mirrors the ROCm/CUDA whole-segment registrations)
	mcError_t err = mcHostRegister(base_addr, seg_size,
				       mcHostRegisterDefault);
	if (err != mcSuccess) {
		SPDLOG_ERROR("mcHostRegister() failed: {}",
			     mcGetErrorString(err));
		return false;
	}

	SPDLOG_INFO("Registered shared memory with MACA: addr={} size={}",
		    base_addr, seg_size);
	maca_host_memory_registered = true;
	return true;
}
#endif
gprobe::gprobe_shm::~gprobe_shm()
{
	if (open_type == shm_open_type::SHM_NO_CREATE) {
		return; // Nothing to do
	}

	void *base_addr = segment.get_address();
#ifdef GPROBE_ENABLE_ROCM_ATTACH
	if (rocm_host_memory_registered) {
		hipError_t err = hipHostUnregister(base_addr);
		// Use fprintf here to avoid spdlog de-initialized issues
		if (err == hipSuccess) {
			fprintf(stderr,
				"gprobe_shm: Unregistered host memory from ROCM\n");
		} else if (err != hipErrorInvalidValue &&
			   err != hipErrorNotInitialized) {
			// Suppress benign teardown errors which are common
			// during shutdown
			fprintf(stderr, "hipHostUnregister() failed: %s\n",
				hipGetErrorString(err));
		}
	}
#endif
#ifdef GPROBE_ENABLE_MACA_ATTACH
	if (maca_host_memory_registered) {
		mcError_t err = mcHostUnregister(base_addr);
		// Use fprintf here to avoid spdlog de-initialized issues
		if (err == mcSuccess) {
			fprintf(stderr,
				"gprobe_shm: Unregistered host memory from MACA\n");
		} else if (err != mcErrorInvalidValue) {
			// Suppress benign teardown errors which are common
			// during shutdown
			fprintf(stderr, "mcHostUnregister() failed: %s\n",
				mcGetErrorString(err));
		}
	}
#endif
#ifdef GPROBE_ENABLE_CUDA_ATTACH
	if (!cuda_host_memory_registered) {
		return;
	}
	cudaError_t err = cudaHostUnregister(base_addr);
	// Use fprintf here to avoid spdlog de-initialized issues
	if (err != cudaSuccess) {
		// Suppress noisy teardown errors which are benign during
		// shutdown
		if (err == cudaErrorCudartUnloading ||
		    err == cudaErrorInvalidValue ||
		    err == cudaErrorInsufficientDriver) {
			return;
		}
		fprintf(stderr, "cudaHostUnregister() failed: %s\n",
			cudaGetErrorString(err));
		return;
	}
	fprintf(stderr, "gprobe_shm: Unregistered host memory from CUDA\n");
#endif
}

bool gprobe_shm::add_pid_into_alive_agent_set(int pid)
{
	if (injected_pids == nullptr) {
		return true;
	}
	auto update = [&]() { injected_pids->insert(pid); };
	pid_set_scoped_lock lock(pid_set_lock);
	if (!lock.owns_lock()) {
		return false;
	}
	update();
	return true;
}
bool gprobe_shm::remove_pid_from_alive_agent_set(int pid)
{
	if (injected_pids == nullptr) {
		return true;
	}
	auto update = [&]() { injected_pids->erase(pid); };
	pid_set_scoped_lock lock(pid_set_lock);
	if (!lock.owns_lock()) {
		return false;
	}
	update();
	return true;
}
bool gprobe_shm::iterate_all_pids_in_alive_agent_set(
	std::function<void(int)> &&cb)
{
	std::vector<int> pids;
	auto snapshot = [&]() {
		if (injected_pids != nullptr) {
			pids.assign(injected_pids->begin(), injected_pids->end());
		}
	};
	pid_set_scoped_lock lock(pid_set_lock);
	if (!lock.owns_lock()) {
		return false;
	}
	snapshot();
	for (auto x : pids) {
		cb(x);
	}
	return true;
}

bool gprobe_shm::add_pid_into_alive_syscall_server_set(int pid)
{
	if (alive_syscall_server_pids == nullptr) {
		return true;
	}
	auto update = [&]() { alive_syscall_server_pids->insert(pid); };
	pid_set_scoped_lock lock(pid_set_lock);
	if (!lock.owns_lock()) {
		return false;
	}
	update();
	return true;
}

bool gprobe_shm::remove_pid_from_alive_syscall_server_set(int pid)
{
	if (alive_syscall_server_pids == nullptr) {
		return true;
	}
	auto update = [&]() { alive_syscall_server_pids->erase(pid); };
	pid_set_scoped_lock lock(pid_set_lock);
	if (!lock.owns_lock()) {
		return false;
	}
	update();
	return true;
}

bool gprobe_shm::iterate_all_pids_in_alive_syscall_server_set(
	std::function<void(int)> &&cb)
{
	std::vector<int> pids;
	auto snapshot = [&]() {
		if (alive_syscall_server_pids != nullptr) {
			pids.assign(alive_syscall_server_pids->begin(),
				    alive_syscall_server_pids->end());
		}
	};
	pid_set_scoped_lock lock(pid_set_lock);
	if (!lock.owns_lock()) {
		return false;
	}
	snapshot();
	for (auto x : pids) {
		cb(x);
	}
	return true;
}

void gprobe_shm::reset_server_state()
{
	if (manager == nullptr) {
		return;
	}
	manager->clear_all(segment);
	if (syscall_installed_pids != nullptr) {
		auto clear_syscall_pids = [&]() {
			syscall_installed_pids->clear();
		};
		pid_set_scoped_lock lock(pid_set_lock);
		if (!lock.owns_lock()) {
			return;
		}
		clear_syscall_pids();
	}
}
#ifdef GPROBE_ENABLE_CUDA_ATTACH
int gprobe_shm::poll_gpu_ringbuf_map(
	int mapfd, const std::function<void(const void *, uint64_t)> &fn)
{
	if (!is_map_fd(mapfd)) {
		SPDLOG_ERROR("Expected {} to be a mapfd", mapfd);
		return -1;
	}
	auto &map_handler =
		std::get<bpf_map_handler>(manager->get_handler(mapfd));

	auto impl_opt = map_handler.try_get_nv_gpu_ringbuf_map_impl();
	if (!impl_opt) {
		SPDLOG_ERROR(
			"Failed to get nv_gpu_ringbuf_map_impl for mapfd {}",
			mapfd);
		return -1;
	}
	auto &impl = *impl_opt;
	return impl->drain_data(fn);
}
#endif
int gprobe_shm::add_memfd_handler(const char *name, int flags)
{
	int fd = open_fake_fd();
	fd = manager->set_handler(fd, memfd_handler(name, flags, segment),
				  segment);
	SPDLOG_DEBUG("Created memfd handler at {}, name {}, flags {}", fd, name,
		     flags);
	return fd;
}
} // namespace gprobe
