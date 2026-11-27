#include "hip_gpu_shared_array_map.hpp"
#include "gprobe_shm.hpp"
#include "gprobe_shm_internal.hpp"
#include "linux/bpf.h"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <unistd.h>

using namespace gprobe;

// Weak no-op: overridden by syscall_server_main.cpp's strong definition when
// linked into libgprobe-syscall-server.so.  When linked into
// libgprobe-agent.so (no syscall-server), this no-op is used instead.
extern "C" __attribute__((weak)) void
gprobe_set_rocm_initializing(bool v) noexcept
{
	(void)v;
}

// RAII guard that sets the global bypass flag so that the syscall-server's
// mmap/munmap/close/ioctl/open/read/fopen overrides do not interfere with
// HIP runtime device initialization and GPU memory mapping.
struct rocm_init_guard {
	rocm_init_guard()
	{
		gprobe_set_rocm_initializing(true);
	}
	~rocm_init_guard()
	{
		gprobe_set_rocm_initializing(false);
	}
};

hip_gpu_shared_array_map_impl::hip_gpu_shared_array_map_impl(
	boost::interprocess::managed_shared_memory &memory, uint64_t value_size,
	uint64_t max_entries)
	: agent_gpu_shared_mem(nullptr), value_size(value_size),
	  max_entries(max_entries), value_buffer(memory.get_segment_manager())
{
	value_buffer.resize(value_size);
	auto total_buffer_size = (uint64_t)value_size * max_entries;
	SPDLOG_INFO(
		"Initializing HIP GPU shared array map, total_buffer_size={}",
		total_buffer_size);
	{
		rocm_init_guard guard;
		(void)hipInit(0);
		if (auto err = hipMalloc(&server_gpu_shared_mem, total_buffer_size);
		    err != hipSuccess) {
			SPDLOG_ERROR(
				"Unable to allocate HIP GPU buffer: {}",
				hipGetErrorString(err));
			throw std::runtime_error(
				"Unable to allocate GPU buffer for hip_gpu_shared_array_map_impl");
		}
		if (auto err = hipMemset(server_gpu_shared_mem, 0, total_buffer_size);
		    err != hipSuccess) {
			SPDLOG_ERROR("Unable to fill GPU buffer with zero: {}",
				     hipGetErrorString(err));
		}
		if (auto err = hipIpcGetMemHandle(&this->gpu_mem_handle,
						  server_gpu_shared_mem);
		    err != hipSuccess) {
			SPDLOG_ERROR(
				"Unable to get HIP IPC handle: {}",
				hipGetErrorString(err));
			throw std::runtime_error(
				"Unable to get HIP IPC handle for hip_gpu_shared_array_map_impl");
		}
	}
	SPDLOG_INFO("HIP GPU shared array map created");
}

void *hip_gpu_shared_array_map_impl::elem_lookup(const void *key)
{
	auto key_val = *(uint32_t *)key;
	if (key_val >= max_entries) {
		errno = ENOENT;
		return nullptr;
	}
	auto base = try_initialize_for_agent_and_get_mapped_address();
	if (shm_holder.global_shared_memory.get_open_type() ==
		    shm_open_type::SHM_OPEN_ONLY &&
	    base == nullptr) {
		errno = EINVAL;
		return nullptr;
	}
	auto err = hipMemcpyDtoH(
		value_buffer.data(),
		(hipDeviceptr_t)((uintptr_t)base +
				 (uint64_t)key_val * value_size),
		value_size);
	if (err != hipSuccess) {
		errno = EIO;
		return nullptr;
	}
	return value_buffer.data();
}

long hip_gpu_shared_array_map_impl::elem_update(const void *key,
					       const void *value,
					       uint64_t flags)
{
	(void)flags;
	auto key_val = *(uint32_t *)key;
	if (key_val >= max_entries) {
		errno = ENOENT;
		return -1;
	}
	auto base = try_initialize_for_agent_and_get_mapped_address();
	if (base == nullptr) {
		errno = EINVAL;
		return -1;
	}
	auto err = hipMemcpyHtoD(
		(hipDeviceptr_t)((uintptr_t)base +
				 (uint64_t)key_val * value_size),
		value, value_size);
	if (err != hipSuccess) {
		errno = EIO;
		return -1;
	}
	return 0;
}

long hip_gpu_shared_array_map_impl::elem_delete(const void *key)
{
	(void)key;
	errno = ENOSYS;
	return -1;
}

int hip_gpu_shared_array_map_impl::map_get_next_key(const void *key,
						     void *next_key)
{
	auto key_val = *(uint32_t *)key;
	if (key_val >= max_entries - 1) {
		errno = ENOENT;
		return -1;
	}
	*(uint32_t *)next_key = key_val + 1;
	return 0;
}

void *hip_gpu_shared_array_map_impl::try_initialize_for_agent_and_get_mapped_address()
{
	if (shm_holder.global_shared_memory.get_open_type() ==
	    shm_open_type::SHM_CREATE_ONLY) {
		return server_gpu_shared_mem;
	}
	if (agent_gpu_shared_mem != nullptr) {
		return agent_gpu_shared_mem;
	}
	auto err = hipIpcOpenMemHandle(
		&agent_gpu_shared_mem, this->gpu_mem_handle,
		hipIpcMemLazyEnablePeerAccess);
	if (err != hipSuccess) {
		SPDLOG_ERROR("Unable to open HIP IPC handle: {}",
			     hipGetErrorString(err));
		return nullptr;
	}
	return agent_gpu_shared_mem;
}

hip_gpu_shared_array_map_impl::~hip_gpu_shared_array_map_impl()
{
	if (agent_gpu_shared_mem != nullptr) {
		(void)hipIpcCloseMemHandle(agent_gpu_shared_mem);
	}
	if (shm_holder.global_shared_memory.get_open_type() !=
	    shm_open_type::SHM_OPEN_ONLY) {
		if (server_gpu_shared_mem != nullptr) {
			(void)hipFree(server_gpu_shared_mem);
		}
	}
}
