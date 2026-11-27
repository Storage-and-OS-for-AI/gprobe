#include "gprobe_shm_internal.hpp"
#include <bpf_attach_ctx.hpp>
#include <hip/hip_runtime.h>
#include <memory>
#include <optional>
#include <mutex>
#include <thread>
#include <spdlog/spdlog.h>

extern "C" {
extern uint64_t gprobe_trace_printk(uint64_t fmt, uint64_t fmt_size, ...);
}

namespace gprobe
{
namespace
{
std::once_flag g_rocm_watcher_atexit_once;
std::mutex g_rocm_watcher_mutex;
std::thread *g_rocm_watcher_thread = nullptr;
std::shared_ptr<std::atomic<bool>> g_rocm_watcher_stop_flag;

void stop_rocm_watcher_thread_at_exit()
{
	std::thread *thread_to_join = nullptr;
	std::shared_ptr<std::atomic<bool>> flag_to_set;
	{
		std::lock_guard<std::mutex> guard(g_rocm_watcher_mutex);
		thread_to_join = g_rocm_watcher_thread;
		flag_to_set = g_rocm_watcher_stop_flag;
		g_rocm_watcher_thread = nullptr;
		g_rocm_watcher_stop_flag.reset();
	}
	if (flag_to_set)
		flag_to_set->store(true, std::memory_order_release);
	if (thread_to_join != nullptr && thread_to_join->joinable())
		thread_to_join->join();
}
} // namespace

void stop_rocm_watcher_before_shm_unmap()
{
	stop_rocm_watcher_thread_at_exit();
}

void bpf_attach_ctx::start_rocm_watcher_thread()
{
	if (!rocm_ctx)
		return;
	if (rocm_watcher_thread.joinable())
		return;
	auto flag = rocm_ctx->rocm_watcher_should_stop;
	rocm_watcher_thread = std::thread([flag, this]() {
		auto *ctx = rocm_ctx.get();

		while (!flag->load(std::memory_order_acquire)) {
			if (ctx != nullptr &&
			    ctx->rocm_shared_mem->flag1 == 1) {
				ctx->rocm_shared_mem->flag1 = 0;
				auto req_id =
					ctx->rocm_shared_mem->request_id;
				auto map_fd = ctx->rocm_shared_mem->map_id;

				SPDLOG_DEBUG(
					"ROCM Received call request id {}, map_fd = {}",
					req_id, map_fd);

				if (req_id ==
				    (int)rocm::HelperOperation::MAP_LOOKUP) {
					const auto &req =
						ctx->rocm_shared_mem->req
							.map_lookup;
					auto &resp =
						ctx->rocm_shared_mem->resp
							.map_lookup;
					auto ptr = gprobe_map_lookup_elem(
						map_fd, req.key);
					resp.value = nullptr;
					if (ptr) {
						// Mirrors the CUDA watcher: hand
						// the GPU a pointer it can
						// actually dereference. Device
						// memory (e.g. GPU IPC maps) is
						// passed through as-is; host
						// memory lives in the shm
						// segment, which the agent
						// registered with
						// hipHostRegister, so convert
						// it with the constant
						// host->device offset measured
						// at the CommSharedMem base.
						// Unlike the CUDA version we
						// only treat an explicit
						// hipMemoryTypeDevice result
						// as a device pointer:
						// ROCm may report registered
						// host memory as unified, and
						// passing the raw host
						// address would fault on GPUs
						// without XNACK.
						const auto host_ptr =
							reinterpret_cast<
								uintptr_t>(
								ptr);
						bool is_device_ptr = false;
						hipPointerAttribute_t attrs{};
						if (hipPointerGetAttributes(
							    &attrs,
							    ptr) ==
						    hipSuccess) {
							is_device_ptr =
								(attrs.type ==
								 hipMemoryTypeDevice);
						}
						if (is_device_ptr) {
							resp.value =
								const_cast<void *>(
									ptr);
						} else {
							const auto comm_host_base =
								reinterpret_cast<
									uintptr_t>(
									ctx->rocm_shared_mem);
							const auto comm_device_base =
								ctx->rocm_shared_mem_device_pointer;
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
						"ROCM: map lookup for {}, result = {:x}",
						map_fd, (uintptr_t)resp.value);
				} else if (req_id ==
					   (int)rocm::HelperOperation::
						   MAP_UPDATE) {
					const auto &req =
						ctx->rocm_shared_mem->req
							.map_update;
					auto &resp =
						ctx->rocm_shared_mem->resp
							.map_update;
					resp.result = gprobe_map_update_elem(
						map_fd, req.key, req.value,
						req.flags);
					SPDLOG_DEBUG(
						"ROCM: map update for {}, result = {}",
						map_fd, resp.result);
				} else if (req_id ==
					   (int)rocm::HelperOperation::
						   MAP_DELETE) {
					const auto &req =
						ctx->rocm_shared_mem->req
							.map_delete;
					auto &resp =
						ctx->rocm_shared_mem->resp
							.map_delete;
					resp.result = gprobe_map_delete_elem(
						map_fd, req.key);
					SPDLOG_DEBUG(
						"ROCM: map delete for {}, result = {}",
						map_fd, resp.result);
				} else if (req_id ==
					   (int)rocm::HelperOperation::
						   TRACE_PRINTK) {
					const auto &req =
						ctx->rocm_shared_mem->req
							.trace_printk;
					auto &resp =
						ctx->rocm_shared_mem->resp
							.trace_printk;
					resp.result = gprobe_trace_printk(
						(uintptr_t)req.fmt,
						req.fmt_size, req.arg1,
						req.arg2, req.arg3);
					SPDLOG_DEBUG(
						"ROCM: trace_printk: {}",
						req.fmt);
				} else if (req_id ==
					   (int)rocm::HelperOperation::
						   GET_CURRENT_PID_TGID) {
					auto &resp =
						ctx->rocm_shared_mem->resp
							.get_tid_pgid;
					static pid_t tgid = getpid();
					static thread_local pid_t tid = -1;
					if (tid == -1) {
						tid = gettid();
					}
					resp.result =
						(((uint64_t)tgid) << 32) |
						(uint32_t)tid;
				} else if (req_id ==
					   (int)rocm::HelperOperation::PUTS) {
					const auto &req =
						ctx->rocm_shared_mem->req
							.puts;
					auto &resp =
						ctx->rocm_shared_mem->resp
							.puts;
					SPDLOG_INFO("eBPF: {}", req.data);
					resp.result = 0;
				} else {
					SPDLOG_WARN(
						"ROCM: Unknown request id {}",
						req_id);
				}

				std::atomic_thread_fence(
					std::memory_order_seq_cst);
				ctx->rocm_shared_mem->flag2 = 1;
				std::atomic_thread_fence(
					std::memory_order_seq_cst);
			}
			std::this_thread::sleep_for(
				std::chrono::milliseconds(1));
		}
		SPDLOG_INFO("Exiting ROCM watcher thread");
	});

	std::call_once(g_rocm_watcher_atexit_once, []() {
		std::atexit(stop_rocm_watcher_thread_at_exit);
	});
	{
		std::lock_guard<std::mutex> guard(g_rocm_watcher_mutex);
		g_rocm_watcher_thread = &rocm_watcher_thread;
		g_rocm_watcher_stop_flag = flag;
	}
	SPDLOG_INFO("ROCM watcher thread started");
}

void bpf_attach_ctx::stop_rocm_watcher_thread()
{
	if (!rocm_ctx)
		return;
	auto flag = rocm_ctx->rocm_watcher_should_stop;
	if (flag)
		flag->store(true, std::memory_order_release);
	{
		std::lock_guard<std::mutex> guard(g_rocm_watcher_mutex);
		if (g_rocm_watcher_thread == &rocm_watcher_thread) {
			g_rocm_watcher_thread = nullptr;
			g_rocm_watcher_stop_flag.reset();
		}
	}
	if (rocm_watcher_thread.joinable()) {
		try {
			rocm_watcher_thread.join();
		} catch (const std::system_error &ex) {
			SPDLOG_WARN(
				"Failed to join ROCM watcher thread: {}",
				ex.what());
			try {
				if (rocm_watcher_thread.joinable())
					rocm_watcher_thread.detach();
			} catch (const std::system_error &detach_ex) {
				SPDLOG_WARN(
					"Failed to detach ROCM watcher thread: {}",
					detach_ex.what());
			}
		}
	}
}

std::vector<attach::MapBasicInfo>
bpf_attach_ctx::create_map_basic_info_rocm(int filled_size)
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
				"ROCM: Copying map fd {} to device, key size={}, value size={}, max ent={}, map_type = {}, gpu_buffer = {:x}",
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

namespace rocm
{

std::optional<std::unique_ptr<rocm::ROCmContext>> create_rocm_context()
{
	SPDLOG_INFO("Initializing ROCM shared memory");
	auto *rocm_shared_mem =
		shm_holder.global_shared_memory.get_rocm_comm_shared_mem();
	if (!rocm_shared_mem) {
		SPDLOG_ERROR(
			"ROCM shared communication memory not initialized in shared segment");
		return std::nullopt;
	}
	memset(rocm_shared_mem, 0, sizeof(*rocm_shared_mem));

	auto rocm_ctx = std::make_optional(
		std::make_unique<rocm::ROCmContext>(rocm_shared_mem));

	SPDLOG_INFO("ROCM context created");
	return rocm_ctx;
}

ROCmContext::~ROCmContext()
{
	// Only unregister when this context performed the registration
	// itself. When the whole shm segment was registered by
	// register_rocm_host_memory(), the unregistration is owned by
	// ~gprobe_shm.
	if (rocm_shared_mem && comm_registered_here) {
		hipHostUnregister((void *)rocm_shared_mem);
	}
	SPDLOG_INFO("Destructing ROCmContext");
}

ROCmContext::ROCmContext(rocm::CommSharedMem *mem)
	: rocm_shared_mem(mem), rocm_shared_mem_device_pointer(0)
{
	auto init_err = hipInit(0);
	if (init_err != hipSuccess) {
		SPDLOG_ERROR("hipInit failed: {}",
			     hipGetErrorString(init_err));
		throw std::runtime_error("Unable to initialize HIP runtime");
	}

	// The whole shm segment is usually registered by
	// register_rocm_host_memory() while opening the shared memory, which
	// already covers the CommSharedMem block. Tolerate the resulting
	// hipErrorHostMemoryAlreadyRegistered instead of failing. When the
	// whole segment could not be registered, registering just the
	// CommSharedMem block here preserves the legacy behavior.
	auto reg_err = hipHostRegister((void *)rocm_shared_mem,
				       sizeof(*rocm_shared_mem),
				       hipHostRegisterDefault);
	if (reg_err == hipErrorHostMemoryAlreadyRegistered) {
		SPDLOG_INFO(
			"CommSharedMem already covered by the whole-segment registration");
		comm_registered_here = false;
	} else if (reg_err != hipSuccess) {
		SPDLOG_ERROR(
			"hipHostRegister failed for CommSharedMem: {}",
			hipGetErrorString(reg_err));
		throw std::runtime_error(
			"Unable to register CommSharedMem for device access");
	} else {
		comm_registered_here = true;
	}

	void *device_ptr = nullptr;
	auto err = hipHostGetDevicePointer(&device_ptr,
					   (void *)rocm_shared_mem, 0);
	if (err != hipSuccess) {
		SPDLOG_ERROR(
			"hipHostGetDevicePointer failed for CommSharedMem: {}",
			hipGetErrorString(err));
		if (comm_registered_here)
			hipHostUnregister((void *)rocm_shared_mem);
		throw std::runtime_error(
			"Unable to get device pointer for CommSharedMem");
	}
	rocm_shared_mem_device_pointer =
		reinterpret_cast<uintptr_t>(device_ptr);
	SPDLOG_INFO("CommSharedMem host {:p} mapped to device {:p}",
		    (void *)rocm_shared_mem, device_ptr);
}

} // namespace rocm
} // namespace gprobe