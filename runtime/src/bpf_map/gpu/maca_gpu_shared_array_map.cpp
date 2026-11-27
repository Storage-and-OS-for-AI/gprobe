// MACA (MetaX) GPU shared array map: see the header for the design
// rationale (host-backed storage in the shm segment; no device IPC).
#include "maca_gpu_shared_array_map.hpp"
#include "gprobe_shm.hpp"
#include "gprobe_shm_internal.hpp"
#include "maca_env_guard.hpp"
#include "linux/bpf.h"
#include "spdlog/spdlog.h"
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <unistd.h>

using namespace gprobe;

// Keep the weak/strong bypass pair so the syscall-server overrides stay
// inert for this map (it performs no MACA runtime calls on the server
// side, but the symbol pair documents the contract and stays available
// for future runtime-using paths).
extern "C" __attribute__((weak)) void
gprobe_set_maca_initializing(bool v) noexcept
{
	(void)v;
}

maca_gpu_shared_array_map_impl::maca_gpu_shared_array_map_impl(
	boost::interprocess::managed_shared_memory &memory, uint64_t value_size,
	uint64_t max_entries)
	: value_data(memory.get_segment_manager()), value_size(value_size),
	  max_entries(max_entries)
{
	value_data.resize(value_size * max_entries);
	SPDLOG_INFO(
		"Initializing MACA GPU shared array map (host-backed), value_size={}, max_entries={}, total={}",
		value_size, max_entries, value_size * max_entries);
}

void *maca_gpu_shared_array_map_impl::elem_lookup(const void *key)
{
	auto key_val = *(uint32_t *)key;
	if (key_val >= max_entries) {
		errno = ENOENT;
		return nullptr;
	}
	// Zero-copy: the caller reads the live slot in the shm segment
	// directly (the GPU probe's writes are visible here immediately).
	return value_data.data() + (uint64_t)key_val * value_size;
}

long maca_gpu_shared_array_map_impl::elem_update(const void *key,
						 const void *value,
						 uint64_t flags)
{
	(void)flags;
	auto key_val = *(uint32_t *)key;
	if (key_val >= max_entries) {
		errno = ENOENT;
		return -1;
	}
	std::copy_n((const uint8_t *)value, value_size,
		    value_data.begin() + (uint64_t)key_val * value_size);
	return 0;
}

long maca_gpu_shared_array_map_impl::elem_delete(const void *key)
{
	(void)key;
	errno = ENOSYS;
	return -1;
}

int maca_gpu_shared_array_map_impl::map_get_next_key(const void *key,
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

void *maca_gpu_shared_array_map_impl::get_gpu_mem_buffer()
{
	maca::maca_runtime_env_guard env_guard;
	void *dev_ptr = nullptr;
	auto err = mcHostGetDevicePointer(&dev_ptr, value_data.data(), 0);
	if (err != mcSuccess) {
		SPDLOG_ERROR(
			"Unable to get device pointer for MACA array map storage: {}",
			mcGetErrorString(err));
		return nullptr;
	}
	return dev_ptr;
}

maca_gpu_shared_array_map_impl::~maca_gpu_shared_array_map_impl()
{
	// Nothing to release: the storage lives in the shm segment and the
	// whole-segment registration is owned by ~gprobe_shm.
}
