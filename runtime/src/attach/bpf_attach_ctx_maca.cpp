// MACA (MetaX) port of bpf_attach_ctx_rocm.cpp: the host-side context
// (MACAContext), the GPU->host watcher thread serving trampoline helper
// requests over CommSharedMem, and the map metadata snapshot handed to the
// GPU. Only compiled with GPROBE_ENABLE_MACA_ATTACH.
#include "gprobe_shm_internal.hpp"
#include <bpf_attach_ctx.hpp>
#include <mc_runtime.h>
#include "maca_env_guard.hpp"
#include <memory>
#include <optional>
#include <mutex>
#include <thread>
#include <spdlog/spdlog.h>

extern "C" {
extern uint64_t gprobe_trace_printk(uint64_t fmt, uint64_t fmt_size, ...);
}

#include <sys/syscall.h>
#include <unistd.h>

// glibc 2.28 (Kylin V10) has no gettid() wrapper (added in glibc 2.30).
static pid_t maca_gettid()
{
	return (pid_t)syscall(SYS_gettid);
}

namespace gprobe
{

namespace
{
std::once_flag g_maca_watcher_atexit_once;
std::mutex g_maca_watcher_mutex;
std::thread *g_maca_watcher_thread = nullptr;
std::shared_ptr<std::atomic<bool>> g_maca_watcher_stop_flag;
} // namespace

static void stop_maca_watcher_thread_at_exit()
{
	auto flag = g_maca_watcher_stop_flag;
	if (flag)
		flag->store(true, std::memory_order_release);
	std::thread *th = nullptr;
	{
		std::lock_guard<std::mutex> guard(g_maca_watcher_mutex);
		th = g_maca_watcher_thread;
		g_maca_watcher_thread = nullptr;
	}
	if (th && th->joinable()) {
		try {
			th->join();
		} catch (const std::system_error &ex) {
			SPDLOG_WARN("Failed to join MACA watcher at exit: {}",
				    ex.what());
		}
	}
}

void stop_maca_watcher_before_shm_unmap()
{
	stop_maca_watcher_thread_at_exit();
}

void bpf_attach_ctx::start_maca_watcher_thread()
{
	if (!maca_ctx)
		return;
	if (maca_watcher_thread.joinable())
		return;
	auto flag = maca_ctx->maca_watcher_should_stop;
	maca_watcher_thread = std::thread([flag, this]() {
		auto *ctx = maca_ctx.get();

		while (!flag->load(std::memory_order_acquire)) {
			if (ctx != nullptr &&
			    ctx->maca_shared_mem->flag1 == 1) {
				ctx->maca_shared_mem->flag1 = 0;
				auto req_id =
					ctx->maca_shared_mem->request_id;
				auto map_fd = ctx->maca_shared_mem->map_id;

				SPDLOG_DEBUG(
					"MACA Received call request id {}, map_fd = {}",
					req_id, map_fd);

				if (req_id ==
				    (int)maca::HelperOperation::MAP_LOOKUP) {
					const auto &req =
						ctx->maca_shared_mem->req
							.map_lookup;
					auto &resp =
						ctx->maca_shared_mem->resp
							.map_lookup;
					auto ptr = gprobe_map_lookup_elem(
						map_fd, req.key);
					resp.value = nullptr;
					if (ptr) {
						// Mirrors the ROCm watcher: hand
						// the GPU a pointer it can
						// actually dereference. Device
						// memory (e.g. GPU IPC maps)
						// is passed through as-is; host
						// memory lives in the shm
						// segment, which the agent
						// registered with
						// mcHostRegister, so convert
						// it with the constant
						// host->device offset measured
						// at the CommSharedMem base.
						// Only treat an explicit
						// mcMemoryTypeDevice result
						// as a device pointer (the
						// GPU may report registered
						// host memory as unified).
						const auto host_ptr =
							reinterpret_cast<
								uintptr_t>(
								ptr);
						bool is_device_ptr = false;
						mcPointerAttribute_t attrs{};
						maca::maca_runtime_env_guard
							env_guard;
						if (mcPointerGetAttributes(
							    &attrs,
							    ptr) ==
						    mcSuccess) {
							is_device_ptr =
								(attrs.type ==
								 mcMemoryTypeDevice);
						}
						if (is_device_ptr) {
							resp.value =
								const_cast<void *>(
									ptr);
						} else {
							const auto comm_host_base =
								reinterpret_cast<
									uintptr_t>(
									ctx->maca_shared_mem);
							const auto comm_device_base =
								ctx->maca_shared_mem_device_pointer;
							const auto offset =
								static_cast<
									intptr_t>(
									host_ptr) -
								static_cast<
									intptr_t>(
									comm_host_base);
							resp.value =
								reinterpret_cast<
									void *>(
									static_cast<
										uintptr_t>(
										static_cast<
											intptr_t>(
											comm_device_base) +
										offset));
						}
					}
					SPDLOG_DEBUG(
						"MACA: map lookup for {}, result = {:x}",
						map_fd, (uintptr_t)resp.value);
				} else if (req_id ==
					   (int)maca::HelperOperation::
						   MAP_UPDATE) {
					const auto &req =
						ctx->maca_shared_mem->req
							.map_update;
					auto &resp =
						ctx->maca_shared_mem->resp
							.map_update;
					resp.result = gprobe_map_update_elem(
						map_fd, req.key, req.value,
						req.flags);
					SPDLOG_DEBUG(
						"MACA: map update for {}, result = {}",
						map_fd, resp.result);
				} else if (req_id ==
					   (int)maca::HelperOperation::
						   MAP_DELETE) {
					const auto &req =
						ctx->maca_shared_mem->req
							.map_delete;
					auto &resp =
						ctx->maca_shared_mem->resp
							.map_delete;
					resp.result = gprobe_map_delete_elem(
						map_fd, req.key);
					SPDLOG_DEBUG(
						"MACA: map delete for {}, result = {}",
						map_fd, resp.result);
				} else if (req_id ==
					   (int)maca::HelperOperation::
						   TRACE_PRINTK) {
					const auto &req =
						ctx->maca_shared_mem->req
							.trace_printk;
					auto &resp =
						ctx->maca_shared_mem->resp
							.trace_printk;
					resp.result = gprobe_trace_printk(
						(uintptr_t)req.fmt,
						req.fmt_size, req.arg1,
						req.arg2, req.arg3);
					SPDLOG_DEBUG(
						"MACA: trace_printk: {}",
						req.fmt);
				} else if (req_id ==
					   (int)maca::HelperOperation::
						   GET_CURRENT_PID_TGID) {
					auto &resp =
						ctx->maca_shared_mem->resp
							.get_tid_pgid;
					static pid_t tgid = getpid();
					static thread_local pid_t tid = -1;
					if (tid == -1) {
						tid = maca_gettid();
					}
					resp.result =
						(((uint64_t)tgid) << 32) |
						(uint32_t)tid;
				} else if (req_id ==
					   (int)maca::HelperOperation::PUTS) {
					const auto &req =
						ctx->maca_shared_mem->req
							.puts;
					auto &resp =
						ctx->maca_shared_mem->resp
							.puts;
					SPDLOG_INFO("eBPF: {}", req.data);
					resp.result = 0;
				} else {
					SPDLOG_WARN(
						"MACA: Unknown request id {}",
						req_id);
				}

				std::atomic_thread_fence(
					std::memory_order_seq_cst);
				ctx->maca_shared_mem->flag2 = 1;
				std::atomic_thread_fence(
					std::memory_order_seq_cst);
			}
			std::this_thread::sleep_for(
				std::chrono::milliseconds(1));
		}
		SPDLOG_INFO("Exiting MACA watcher thread");
	});

	std::call_once(g_maca_watcher_atexit_once, []() {
		std::atexit(stop_maca_watcher_thread_at_exit);
	});
	{
		std::lock_guard<std::mutex> guard(g_maca_watcher_mutex);
		g_maca_watcher_thread = &maca_watcher_thread;
		g_maca_watcher_stop_flag = flag;
	}
	SPDLOG_INFO("MACA watcher thread started");
}

void bpf_attach_ctx::stop_maca_watcher_thread()
{
	if (!maca_ctx)
		return;
	auto flag = maca_ctx->maca_watcher_should_stop;
	if (flag)
		flag->store(true, std::memory_order_release);
	{
		std::lock_guard<std::mutex> guard(g_maca_watcher_mutex);
		if (g_maca_watcher_thread == &maca_watcher_thread) {
			g_maca_watcher_thread = nullptr;
			g_maca_watcher_stop_flag.reset();
		}
	}
	if (maca_watcher_thread.joinable()) {
		try {
			maca_watcher_thread.join();
		} catch (const std::system_error &ex) {
			SPDLOG_WARN(
				"Failed to join MACA watcher thread: {}",
				ex.what());
			try {
				if (maca_watcher_thread.joinable())
					maca_watcher_thread.detach();
			} catch (const std::system_error &detach_ex) {
				SPDLOG_WARN(
					"Failed to detach MACA watcher thread: {}",
					detach_ex.what());
			}
		}
	}
}

std::vector<attach::MapBasicInfo>
bpf_attach_ctx::create_map_basic_info_maca(int filled_size)
{
	std::vector<attach::MapBasicInfo> local_basic_info(filled_size);
	for (auto &entry : local_basic_info) {
		entry.enabled = false;
		entry.key_size = 0;
		entry.value_size = 0;
		entry.max_entries = 0;
		entry.map_type = 0;
		entry.extra_buffer = nullptr;
		entry.max_thread_count = 0;
	}
	const auto &handler_manager =
		*shm_holder.global_shared_memory.get_manager();
	for (size_t i = 0; i < handler_manager.size(); i++) {
		const auto &current_handler =
			handler_manager.get_handler(i);
		if (std::holds_alternative<bpf_map_handler>(
			    current_handler)) {
			auto &local = local_basic_info[i];
			const auto &map =
				std::get<bpf_map_handler>(current_handler);
			auto gpu_buffer = map.get_gpu_map_extra_buffer();
			SPDLOG_INFO(
				"MACA: Copying map fd {} to device, key size={}, value size={}, max ent={}, map_type = {}, gpu_buffer = {:x}",
				i, map.get_key_size(),
				map.get_value_size(),
				map.get_max_entries(), (int)map.type,
				(uintptr_t)gpu_buffer);

			if (i >= local_basic_info.size()) {
				SPDLOG_ERROR(
					"Too large map fd: {}, max to be {}",
					i, local_basic_info.size());
				return {};
			}
			local.enabled = true;
			local.key_size = map.get_key_size();
			local.value_size = map.get_value_size();
			local.max_entries = map.get_max_entries();
			local.map_type = (int)map.type;
			local.extra_buffer = gpu_buffer;
			local.max_thread_count =
				map.get_gpu_map_max_thread_count();
		}
	}
	return local_basic_info;
}

namespace maca
{

std::optional<std::unique_ptr<maca::MACAContext>> create_maca_context()
{
	SPDLOG_INFO("Initializing MACA shared memory");
	auto *maca_shared_mem =
		shm_holder.global_shared_memory.get_maca_comm_shared_mem();
	if (!maca_shared_mem) {
		SPDLOG_ERROR(
			"MACA shared communication memory not initialized in shared segment");
		return std::nullopt;
	}
	memset(maca_shared_mem, 0, sizeof(*maca_shared_mem));

	auto maca_ctx = std::make_optional(
		std::make_unique<maca::MACAContext>(maca_shared_mem));

	SPDLOG_INFO("MACA context created");
	return maca_ctx;
}

MACAContext::~MACAContext()
{
	maca::maca_runtime_env_guard env_guard;
	// Only unregister when this context performed the registration
	// itself. When the whole shm segment was registered by
	// register_maca_host_memory(), the unregistration is owned by
	// ~gprobe_shm.
	if (maca_shared_mem && comm_registered_here) {
		mcHostUnregister((void *)maca_shared_mem);
	}
	SPDLOG_INFO("Destructing MACAContext");
}

MACAContext::MACAContext(maca::CommSharedMem *mem)
	: maca_shared_mem(mem), maca_shared_mem_device_pointer(0)
{
	// Covers every runtime call in the constructor: mcInit's zip probe
	// and any other internally forked helper must not re-enter this
	// library via LD_PRELOAD while the shm flock is held.
	maca::maca_runtime_env_guard env_guard;
	auto init_err = mcInit(0);
	if (init_err != mcSuccess) {
		SPDLOG_ERROR("mcInit failed: {}",
			     mcGetErrorString(init_err));
		throw std::runtime_error("Unable to initialize MACA runtime");
	}
	// Establish the device context before the instrumented module is
	// loaded: without an active device, mcModuleLaunchKernel on the
	// module's functions fails with mcErrorMemoryValueTooLarge (the
	// kernel argument marshaling cannot resolve the function's device
	// context). Mirrors the CLI flow (run_verify: mcInit +
	// mcSetDevice before mcModuleLoadData).
	auto dev_err = mcSetDevice(0);
	if (dev_err != mcSuccess) {
		SPDLOG_WARN("mcSetDevice(0) failed: {}",
			    mcGetErrorString(dev_err));
	}

	// The whole shm segment is usually registered by
	// register_maca_host_memory() while opening the shared memory, which
	// already covers the CommSharedMem block. Tolerate the resulting
	// mcErrorHostMemoryAlreadyRegistered instead of failing. When the
	// whole segment could not be registered, registering just the
	// CommSharedMem block here preserves the legacy behavior.
	auto reg_err = mcHostRegister((void *)maca_shared_mem,
				      sizeof(*maca_shared_mem),
				      mcHostRegisterDefault);
	if (reg_err == mcErrorHostMemoryAlreadyRegistered) {
		SPDLOG_INFO(
			"CommSharedMem already covered by the whole-segment registration");
		comm_registered_here = false;
	} else if (reg_err != mcSuccess) {
		SPDLOG_ERROR(
			"mcHostRegister failed for CommSharedMem: {}",
			mcGetErrorString(reg_err));
		throw std::runtime_error(
			"Unable to register CommSharedMem for device access");
	} else {
		comm_registered_here = true;
	}

	void *device_ptr = nullptr;
	auto err = mcHostGetDevicePointer(&device_ptr,
					  (void *)maca_shared_mem, 0);
	if (err != mcSuccess) {
		SPDLOG_ERROR(
			"mcHostGetDevicePointer failed for CommSharedMem: {}",
			mcGetErrorString(err));
		if (comm_registered_here)
			mcHostUnregister((void *)maca_shared_mem);
		throw std::runtime_error(
			"Unable to get device pointer for CommSharedMem");
	}
	maca_shared_mem_device_pointer =
		reinterpret_cast<uintptr_t>(device_ptr);
	SPDLOG_INFO("CommSharedMem host {:p} mapped to device {:p}",
		    (void *)maca_shared_mem, device_ptr);
}

} // namespace maca
} // namespace gprobe
