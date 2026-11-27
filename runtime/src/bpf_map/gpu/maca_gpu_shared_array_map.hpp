#ifndef _MACA_GPU_SHARED_ARRAY_MAP_HPP
#define _MACA_GPU_SHARED_ARRAY_MAP_HPP

#include "bpf_map/map_common_def.hpp"
#include <mc_runtime.h>
#include <cstdint>

namespace gprobe
{

// MACA (MetaX) GPU shared array map. The MACA driver restricts
// mcIpcOpenMemHandle to fork+exec descendants of the exporting process,
// which does not fit the server/agent model (independently spawned
// processes), so unlike the ROCm/CUDA ports this implementation keeps the
// value storage in the boost shm segment:
//   - the GPU side (the trampoline fast path / eBPF probe) accesses it
//     through the device mapping of the whole registered shm segment
//     (register_maca_host_memory), via the pointer returned by
//     get_gpu_mem_buffer() — the ROCm hash-map "zero-copy registered host
//     memory" pathway, applied to the array map;
//   - the host side (syscall-server) reads/writes the same storage
//     directly through the shm — updates are visible to both sides
//     immediately (no memcpy at all).
class maca_gpu_shared_array_map_impl {
	bytes_vec value_data;
	uint64_t value_size;
	uint64_t max_entries;

    public:
	const static bool should_lock = true;

	maca_gpu_shared_array_map_impl(
		boost::interprocess::managed_shared_memory &memory,
		uint64_t value_size, uint64_t max_entries);

	void *elem_lookup(const void *key);

	long elem_update(const void *key, const void *value, uint64_t flags);

	long elem_delete(const void *key);

	int map_get_next_key(const void *key, void *next_key);

	// Device-visible address of the value storage (agent side; the whole
	// shm segment is registered by register_maca_host_memory, so the
	// returned device pointer aliases the same memory the host sees).
	void *get_gpu_mem_buffer();
	uint64_t get_max_thread_count() const
	{
		return 1;
	}
	virtual ~maca_gpu_shared_array_map_impl();
};

} // namespace gprobe

#endif
