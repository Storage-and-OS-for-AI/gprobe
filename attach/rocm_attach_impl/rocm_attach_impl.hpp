#ifndef _GPROBE_ROCM_ATTACH_IMPL_HPP
#define _GPROBE_ROCM_ATTACH_IMPL_HPP

#include <base_attach_impl.hpp>
#include <dlfcn.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <ebpf_inst.h>
#include <optional>
#include <atomic>
#include <chrono>

struct ihipModule_t;
struct ihipModuleSymbol_t;
struct ihipStream_t;
struct ihipEvent_t;
typedef struct ihipModule_t *hipModule_t;
typedef struct ihipModuleSymbol_t *hipFunction_t;
typedef struct ihipStream_t *hipStream_t;
typedef struct ihipEvent_t *hipEvent_t;

namespace gprobe
{
namespace attach
{

constexpr int ATTACH_ROCM_PROBE = 8;
constexpr int ATTACH_ROCM_RETPROBE = 9;

struct MapBasicInfo {
	bool enabled;
	int key_size;
	int value_size;
	int max_entries;
	int map_type;
	void *extra_buffer;
	uint64_t max_thread_count;
};

// One attach request as seen by the attach manager: a single eBPF program
// bound to one kernel with one probe type. Mirrors nv_attach_entry.
struct rocm_attach_entry {
	std::string kernel_name;
	// "kprobe" / "kretprobe"
	std::string probe_type;
	std::vector<ebpf_inst> instructions;
};

// All probes compiled into one instrumented hsaco, as (probe_type,
// instructions) pairs. A single instrumented kernel can host the kprobe and
// the kretprobe of the same kernel simultaneously.
using ebpf_probe_programs =
	std::vector<std::pair<std::string, std::vector<ebpf_inst>>>;

struct instrumented_kernel_entry {
	std::string kernel_name;
	hipModule_t hsaco_module = nullptr;
	hipFunction_t hip_function = nullptr;
	std::vector<uint8_t> hsaco_data;
	// Snapshot of the probes this hsaco was generated from (the live set is
	// always re-derived from hook_entries when regenerating).
	ebpf_probe_programs ebpf_programs;
};

class rocm_attach_impl final : public base_attach_impl {
    public:
	rocm_attach_impl();
	~rocm_attach_impl() override;

	int create_attach_with_ebpf_callback(
		ebpf_run_callback &&cb,
		const attach_private_data &private_data,
		int attach_type) override;

	int detach_by_id(int id) override;
	void register_custom_helpers(
		ebpf_helper_register_callback register_callback) override;

	std::optional<hipFunction_t>
	find_instrumented_hip_function(const std::string &name) const;

	bool is_enabled() const noexcept;
	const char *get_default_helper_path() const;

	void *frida_interceptor = nullptr;
	void *frida_listener = nullptr;

	const std::map<std::string, instrumented_kernel_entry> &
	get_instrumented_kernels() const
	{
		return instrumented_kernels;
	}

	void mirror_hip_memcpy_to_symbol(const void *symbol,
					 const void *src, size_t count,
					 size_t offset, int kind);

	bool mirror_hip_memcpy_from_symbol(void *dst, const void *symbol,
					    size_t count, size_t offset,
					    int kind);

	void record_kernel_function_name(hipFunction_t func,
					 const std::string &name);
	std::optional<std::string>
	find_kernel_name_by_function(hipFunction_t func) const;

	void record_patched_launch(hipStream_t stream);
	void clear_patched_state_for_next_session();

    private:
	std::map<std::string, instrumented_kernel_entry>
		instrumented_kernels;

	// Active attach entries by local attach id (returned by
	// create_attach_with_ebpf_callback). The authoritative live set of
	// probes: instrumented_kernels entries are regenerated from it.
	std::map<int, rocm_attach_entry> hook_entries;
	mutable std::mutex hook_entries_mutex;

	std::atomic<bool> enabled{ true };

	mutable std::mutex patched_global_cache_mutex;
	std::unordered_map<std::string, std::pair<void *, size_t> >
		patched_global_by_name;

	mutable std::mutex function_name_mutex;
	std::unordered_map<hipFunction_t, std::string>
		kernel_name_by_function;

	mutable std::mutex launch_event_mutex;
	std::unordered_map<hipStream_t, hipEvent_t>
		pending_launch_events_by_stream;

	void wait_for_patched_launch_events(
		std::chrono::milliseconds timeout);
};

void rocm_attach_impl_setup_frida_hooks(rocm_attach_impl *impl);
std::string rocm_lookup_variable_name(const void *symbol);
void rocm_clear_global_state();

} // namespace attach
} // namespace gprobe

#endif
