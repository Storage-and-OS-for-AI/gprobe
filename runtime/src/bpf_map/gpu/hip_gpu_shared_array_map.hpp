#ifndef _HIP_GPU_SHARED_ARRAY_MAP_HPP
#define _HIP_GPU_SHARED_ARRAY_MAP_HPP

#include "bpf_map/map_common_def.hpp"
#include "hip/hip_runtime.h"
#include <cstdint>

namespace gprobe
{

class hip_gpu_shared_array_map_impl {
	hipIpcMemHandle_t gpu_mem_handle;
	void *server_gpu_shared_mem = nullptr;
	void *agent_gpu_shared_mem = nullptr;
	uint64_t value_size;
	uint64_t max_entries;

	bytes_vec value_buffer;

    public:
	const static bool should_lock = true;

	hip_gpu_shared_array_map_impl(
		boost::interprocess::managed_shared_memory &memory,
		uint64_t value_size, uint64_t max_entries);

	void *elem_lookup(const void *key);

	long elem_update(const void *key, const void *value, uint64_t flags);

	long elem_delete(const void *key);

	int map_get_next_key(const void *key, void *next_key);

	void *get_gpu_mem_buffer()
	{
		return try_initialize_for_agent_and_get_mapped_address();
	}
	uint64_t get_max_thread_count() const
	{
		return 1;
	}
	virtual ~hip_gpu_shared_array_map_impl();

	void *try_initialize_for_agent_and_get_mapped_address();
};

} // namespace gprobe

#endif