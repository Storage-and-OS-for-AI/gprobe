#include <hip/hip_runtime.h>
#include <atomic>
#include <cstdint>
#include <cstdio>

// Must match GPU_HELPER_MAX_BUF on the host side
// (runtime/include/bpf_attach_ctx.hpp, default 1 << 20): the union layout
// (and therefore the offsets of map_update.value/flags and the whole resp)
// depends on this constant, so a mismatch silently desynchronizes the
// GPU and host views of CommSharedMem.
static constexpr int GPU_HELPER_MAX_BUF = 1 << 20;

enum class HelperOperation {
	MAP_LOOKUP = 1,
	MAP_UPDATE = 2,
	MAP_DELETE = 3,
	MAP_GET_NEXT_KEY = 4,
	TRACE_PRINTK = 6,
	GET_CURRENT_PID_TGID = 14,
	PUTS = 501
};

union HelperCallRequest {
	struct {
		char key[GPU_HELPER_MAX_BUF];
	} map_lookup;
	struct {
		char key[GPU_HELPER_MAX_BUF];
		char value[GPU_HELPER_MAX_BUF];
		uint64_t flags;
	} map_update;
	struct {
		char key[GPU_HELPER_MAX_BUF];
	} map_delete;
	struct {
		char fmt[1000];
		int fmt_size;
		unsigned long arg1, arg2, arg3;
	} trace_printk;
	struct {
		char data[10000];
	} puts;
	struct {
	} get_tid_pgid;
};

union HelperCallResponse {
	struct {
		int result;
	} map_update, map_delete, trace_printk, puts;
	struct {
		const void *value;
	} map_lookup;
	struct {
		uint64_t result;
	} get_tid_pgid;
};

struct CommSharedMem {
	int flag1;
	int flag2;
	int occupy_flag;
	int request_id;
	long map_id;
	HelperCallRequest req;
	HelperCallResponse resp;
	uint64_t time_sum[8];
};

const int BPF_MAP_TYPE_GPU_HASH_MAP = 1501;
const int BPF_MAP_TYPE_PERGPUTD_ARRAY_MAP = 1502;
const int BPF_MAP_TYPE_GPU_ARRAY_MAP = 1503;
const int BPF_MAP_TYPE_GPU_KERNEL_SHARED_ARRAY_MAP = 1504;
const int BPF_MAP_TYPE_GPU_RINGBUF_MAP = 1527;
const int BPF_MAP_TYPE_PERGPUTD_ARRAY_HOST_MAP = 1512;
const int BPF_MAP_TYPE_GPU_ARRAY_HOST_MAP = 1513;

struct MapBasicInfo {
	bool enabled;
	int key_size;
	int value_size;
	int max_entries;
	int map_type;
	void *extra_buffer;
	uint64_t max_thread_count;
};

__device__ __forceinline__ uint64_t read_globaltimer()
{
	return clock64();
}

__constant__ uintptr_t constData;
__constant__ MapBasicInfo map_info[1024];

extern "C" __device__ void spin_lock(volatile int *lock)
{
	while (atomicCAS((int *)lock, 0, 1) != 0) {
	}
}

extern "C" __device__ void spin_unlock(volatile int *lock)
{
	__atomic_store_n(const_cast<int *>(lock), 0, __ATOMIC_RELEASE);
}

__device__ int __gprobe_comm_lock = 0;

extern "C" __device__ HelperCallResponse make_helper_call(long map_id,
							  int req_id)
{
	CommSharedMem *g_data = (CommSharedMem *)constData;
	int lane_id = __lane_id();
	HelperCallResponse my_resp = {};

	unsigned long long active_mask = __activemask();
	for (int active_lane = 0; active_lane < warpSize; active_lane++) {
		bool lane_is_active = (active_mask >> active_lane) & 1;

		if (lane_is_active && lane_id == active_lane) {
			spin_lock(&__gprobe_comm_lock);

			g_data->request_id = req_id;
			g_data->map_id = map_id;

			__threadfence_system();
			__atomic_store_n(&g_data->flag1, 1,
					 __ATOMIC_RELEASE);

			int flag2_val;
			do {
				__threadfence_system();
				flag2_val = __atomic_load_n(
					&g_data->flag2, __ATOMIC_ACQUIRE);
			} while (flag2_val == 0);

			__atomic_store_n(&g_data->flag2, 0, __ATOMIC_RELEASE);
			__threadfence_system();

			my_resp = g_data->resp;

			spin_unlock(&__gprobe_comm_lock);
		}

		__syncwarp(active_mask);
	}

	return my_resp;
}

extern "C" __device__ inline void simple_memcpy(void *dst, void *src, int sz)
{
	for (int i = 0; i < sz; i++)
		((char *)dst)[i] = ((char *)src)[i];
}

__device__ uint64_t getGlobalThreadId()
{
	int x = hipBlockIdx_x * hipBlockDim_x + hipThreadIdx_x;
	int y = hipBlockIdx_y * hipBlockDim_y + hipThreadIdx_y;
	int z = hipBlockIdx_z * hipBlockDim_z + hipThreadIdx_z;
	int width = hipGridDim_x * hipBlockDim_x;
	int height = hipGridDim_y * hipBlockDim_y;
	return ((uint64_t)z * width * height) + (y * width) + x;
}

__device__ void *array_map_offset(uint64_t idx, const MapBasicInfo &info,
				  uint64_t map)
{
	if (info.max_thread_count <= getGlobalThreadId()) {
		printf("WARNING: getGlobalThreadId(%lu) exceeds max_thread_count (%lu) of map %lu\n",
		       getGlobalThreadId(), info.max_thread_count, map);
	}
	return (void *)((uintptr_t)info.extra_buffer +
			idx * info.max_thread_count * info.value_size +
			getGlobalThreadId() * info.value_size);
}

extern "C" __noinline__ __device__ uint64_t _bpf_helper_ext_0001(
	uint64_t map, uint64_t key, uint64_t a, uint64_t b, uint64_t c)
{
	CommSharedMem *global_data = (CommSharedMem *)constData;
	auto &req = global_data->req;
	const auto &map_info = ::map_info[map];
	if (map_info.map_type == BPF_MAP_TYPE_PERGPUTD_ARRAY_MAP) {
		auto real_key = *(uint32_t *)(uintptr_t)key;
		auto offset = array_map_offset(real_key, map_info, map);
		return (uint64_t)(uintptr_t)offset;
	}
	if (map_info.map_type == BPF_MAP_TYPE_GPU_ARRAY_MAP ||
	    map_info.map_type == BPF_MAP_TYPE_GPU_KERNEL_SHARED_ARRAY_MAP) {
		auto real_key = *(uint32_t *)(uintptr_t)key;
		auto base = (char *)map_info.extra_buffer;
		return (uint64_t)(uintptr_t)(base +
					     (uint64_t)real_key *
						     map_info.value_size);
	}
	if (map_info.map_type == BPF_MAP_TYPE_PERGPUTD_ARRAY_HOST_MAP) {
		auto real_key = *(uint32_t *)(uintptr_t)key;
		auto offset = array_map_offset(real_key, map_info, map);
		__threadfence_system();
		return (uint64_t)(uintptr_t)offset;
	}
	if (map_info.map_type == BPF_MAP_TYPE_GPU_ARRAY_HOST_MAP) {
		auto real_key = *(uint32_t *)(uintptr_t)key;
		auto base = (char *)map_info.extra_buffer;
		__threadfence_system();
		return (uint64_t)(uintptr_t)(base +
					     (uint64_t)real_key *
						     map_info.value_size);
	}
	simple_memcpy(&req.map_lookup.key, (void *)(uintptr_t)key,
		      map_info.key_size);
	HelperCallResponse resp =
		make_helper_call((long)map, (int)HelperOperation::MAP_LOOKUP);
	return (uintptr_t)resp.map_lookup.value;
}

extern "C" __noinline__ __device__ uint64_t _bpf_helper_ext_0002(
	uint64_t map, uint64_t key, uint64_t value, uint64_t flags, uint64_t a)
{
	CommSharedMem *global_data = (CommSharedMem *)constData;
	auto &req = global_data->req;
	const auto &map_info = ::map_info[map];
	if (map_info.map_type == BPF_MAP_TYPE_PERGPUTD_ARRAY_MAP) {
		auto real_key = *(uint32_t *)(uintptr_t)key;
		auto offset = array_map_offset(real_key, map_info, map);
		simple_memcpy(offset, (void *)(uintptr_t)value,
			      map_info.value_size);
		return 0;
	}
	if (map_info.map_type == BPF_MAP_TYPE_GPU_ARRAY_MAP ||
	    map_info.map_type == BPF_MAP_TYPE_GPU_KERNEL_SHARED_ARRAY_MAP) {
		auto real_key = *(uint32_t *)(uintptr_t)key;
		auto base = (char *)map_info.extra_buffer;
		auto dst = (void *)(uintptr_t)(base +
					       (uint64_t)real_key *
						       map_info.value_size);
		simple_memcpy(dst, (void *)(uintptr_t)value,
			      map_info.value_size);
		__threadfence_system();
		return 0;
	}
	if (map_info.map_type == BPF_MAP_TYPE_PERGPUTD_ARRAY_HOST_MAP) {
		auto real_key = *(uint32_t *)(uintptr_t)key;
		auto offset = array_map_offset(real_key, map_info, map);
		simple_memcpy(offset, (void *)(uintptr_t)value,
			      map_info.value_size);
		__threadfence_system();
		return 0;
	}
	if (map_info.map_type == BPF_MAP_TYPE_GPU_ARRAY_HOST_MAP) {
		auto real_key = *(uint32_t *)(uintptr_t)key;
		auto base = (char *)map_info.extra_buffer;
		auto dst = (void *)(uintptr_t)(base +
					       (uint64_t)real_key *
						       map_info.value_size);
		simple_memcpy(dst, (void *)(uintptr_t)value,
			      map_info.value_size);
		__threadfence_system();
		return 0;
	}
	simple_memcpy(&req.map_update.key, (void *)(uintptr_t)key,
		      map_info.key_size);
	simple_memcpy(&req.map_update.value, (void *)(uintptr_t)value,
		      map_info.value_size);
	req.map_update.flags = (uintptr_t)flags;
	HelperCallResponse resp =
		make_helper_call((long)map, (int)HelperOperation::MAP_UPDATE);
	return resp.map_update.result;
}

extern "C" __noinline__ __device__ uint64_t _bpf_helper_ext_0003(
	uint64_t map, uint64_t key, uint64_t a, uint64_t b, uint64_t c)
{
	CommSharedMem *global_data = (CommSharedMem *)constData;
	auto &req = global_data->req;
	const auto &map_info = ::map_info[map];
	simple_memcpy(&req.map_delete.key, (void *)(uintptr_t)key,
		      map_info.key_size);
	HelperCallResponse resp =
		make_helper_call((long)map, (int)HelperOperation::MAP_DELETE);
	return resp.map_delete.result;
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0006(uint64_t fmt, uint64_t fmt_size, uint64_t arg1,
		     uint64_t arg2, uint64_t arg3)
{
	CommSharedMem *global_data = (CommSharedMem *)constData;
	auto &req = global_data->req;
	char *out = (char *)req.trace_printk.fmt;
	char *in = (char *)(uintptr_t)fmt;
	for (auto i = 0; i < fmt_size; i++) {
		out[i] = in[i];
	}
	req.trace_printk.fmt_size = fmt_size;
	req.trace_printk.arg1 = arg1;
	req.trace_printk.arg2 = arg2;
	req.trace_printk.arg3 = arg3;
	HelperCallResponse resp =
		make_helper_call(0, (int)HelperOperation::TRACE_PRINTK);
	return resp.trace_printk.result;
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0014(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	HelperCallResponse resp =
		make_helper_call(0, (int)HelperOperation::GET_CURRENT_PID_TGID);
	return resp.get_tid_pgid.result;
}

struct ringbuf_header {
	uint64_t head;
	uint64_t tail;
	int dirty;
};

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0025(uint64_t ctx, uint64_t map, uint64_t flags, uint64_t data,
		     uint64_t data_size)
{
	const auto &map_info = ::map_info[map];
	if (map_info.map_type == BPF_MAP_TYPE_GPU_RINGBUF_MAP) {
		auto tid = getGlobalThreadId();
		if (tid >= map_info.max_thread_count) {
			return 1;
		}
		auto entry_size = sizeof(ringbuf_header) +
				  map_info.max_entries * (sizeof(uint64_t) +
							  map_info.value_size);
		auto header = (ringbuf_header *)(uintptr_t)(
			tid * entry_size + (char *)map_info.extra_buffer);
		if (header->tail - header->head == map_info.max_entries) {
			return 2;
		}
		header->dirty = 1;
		auto tail_to_put =
			__atomic_fetch_add(&header->tail, 1, __ATOMIC_SEQ_CST);
		auto real_tail = tail_to_put % map_info.max_entries;
		auto buffer = ((char *)header) + sizeof(ringbuf_header) +
			      real_tail * (sizeof(uint64_t) +
					   map_info.value_size);
		*(uint64_t *)(uintptr_t)buffer = data_size;
		simple_memcpy(buffer + sizeof(uint64_t),
			      (void *)(uintptr_t)data, data_size);
		header->dirty = 0;
		return 0;
	} else {
		printf("Calling bpf_perf_event_output on unsupported map!");
		return 1;
	}
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0501(uint64_t data, uint64_t, uint64_t, uint64_t, uint64_t)
{
	CommSharedMem *global_data = (CommSharedMem *)constData;
	auto &req = global_data->req.puts;

	const char *input = (const char *)data;
	int idx = 0;
	while (input[idx]) {
		req.data[idx] = input[idx];
		idx++;
	}
	req.data[idx] = 0;
	HelperCallResponse resp =
		make_helper_call(0, (int)HelperOperation::PUTS);
	return resp.puts.result;
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0502(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	return read_globaltimer();
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0503(uint64_t x, uint64_t y, uint64_t z, uint64_t, uint64_t)
{
	*(uint64_t *)(uintptr_t)x = hipBlockIdx_x;
	*(uint64_t *)(uintptr_t)y = hipBlockIdx_y;
	*(uint64_t *)(uintptr_t)z = hipBlockIdx_z;
	return 0;
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0504(uint64_t x, uint64_t y, uint64_t z, uint64_t, uint64_t)
{
	*(uint64_t *)(uintptr_t)x = hipBlockDim_x;
	*(uint64_t *)(uintptr_t)y = hipBlockDim_y;
	*(uint64_t *)(uintptr_t)z = hipBlockDim_z;
	return 0;
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0505(uint64_t x, uint64_t y, uint64_t z, uint64_t, uint64_t)
{
	*(uint64_t *)(uintptr_t)x = hipThreadIdx_x;
	*(uint64_t *)(uintptr_t)y = hipThreadIdx_y;
	*(uint64_t *)(uintptr_t)z = hipThreadIdx_z;
	return 0;
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0506(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	__threadfence_system();
	return 0;
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0507(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	return 0;
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0508(uint64_t x, uint64_t y, uint64_t z, uint64_t, uint64_t)
{
	*(uint64_t *)(uintptr_t)x = hipGridDim_x;
	*(uint64_t *)(uintptr_t)y = hipGridDim_y;
	*(uint64_t *)(uintptr_t)z = hipGridDim_z;
	return 0;
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0509(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	return __builtin_amdgcn_workgroup_id_x();
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0510(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	return hipThreadIdx_x / warpSize;
}

extern "C" __noinline__ __device__ uint64_t
_bpf_helper_ext_0511(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	return __lane_id();
}