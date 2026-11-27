#include "rocm_attach_impl.hpp"
#include "rocm_attach_private_data.hpp"
#include "spdlog/spdlog.h"
#include <llvmbpf.hpp>
#include <hip/hip_runtime.h>
#include <filesystem>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace gprobe
{
namespace attach
{

static std::string find_default_helper_path()
{
	const char *env = std::getenv("GPROBE_ROCM_HELPER_PATH");
	if (env) {
		return std::string(env);
	}
	std::filesystem::path p = DEFAULT_ROCM_HELPER_PATH;
	return p.string();
}

rocm_attach_impl::rocm_attach_impl()
{
	rocm_attach_impl_setup_frida_hooks(this);
	SPDLOG_INFO("rocm_attach_impl: Frida hooks installed");
}

rocm_attach_impl::~rocm_attach_impl()
{
	for (auto &[name, entry] : instrumented_kernels) {
		if (entry.hsaco_module) {
			(void)hipModuleUnload(entry.hsaco_module);
		}
	}
	instrumented_kernels.clear();
}

bool rocm_attach_impl::is_enabled() const noexcept
{
	return enabled.load(std::memory_order_acquire);
}

const char *rocm_attach_impl::get_default_helper_path() const
{
	static std::string path = find_default_helper_path();
	return path.c_str();
}

std::optional<hipFunction_t>
rocm_attach_impl::find_instrumented_hip_function(
	const std::string &name) const
{
	auto it = instrumented_kernels.find(name);
	if (it != instrumented_kernels.end()) {
		return it->second.hip_function;
	}
	return std::nullopt;
}

int rocm_attach_impl::create_attach_with_ebpf_callback(
	ebpf_run_callback &&cb, const attach_private_data &private_data,
	int attach_type)
{
	auto &data =
		dynamic_cast<const rocm_attach_private_data &>(private_data);

	SPDLOG_INFO("rocm_attach_impl: creating attach for program {}",
		    data.program_name);

	if (data.func_names.empty()) {
		SPDLOG_ERROR("rocm_attach_impl: no kernel names specified");
		return -EINVAL;
	}

	const auto &kernel_name = data.func_names[0];
	std::string mcpu = "gfx1100";
	const char *mcpu_env = std::getenv("GPROBE_ROCM_MCPU");
	if (mcpu_env) {
		mcpu = mcpu_env;
	}

	std::string probe_type =
		(attach_type == ATTACH_ROCM_RETPROBE) ? "kretprobe" :
							"kprobe";

	const int id = allocate_id();

	// Register the attach entry first, then derive the live set of probes
	// for this kernel from hook_entries: a regenerated hsaco must contain
	// every active probe of the kernel (e.g. kprobe + kretprobe), and the
	// set must not include probes detached in between (detach does not
	// regenerate the hsaco, so instrumented_kernel_entry.ebpf_programs is
	// only a snapshot of the last build).
	ebpf_probe_programs programs;
	{
		std::lock_guard<std::mutex> guard(hook_entries_mutex);
		for (const auto &kv : hook_entries) {
			if (kv.second.kernel_name == kernel_name &&
			    kv.second.probe_type == probe_type) {
				SPDLOG_ERROR(
					"rocm_attach_impl: a {} program is already attached to kernel {}",
					probe_type, kernel_name);
				return -EEXIST;
			}
		}
		rocm_attach_entry attach_entry;
		attach_entry.kernel_name = kernel_name;
		attach_entry.probe_type = probe_type;
		attach_entry.instructions = data.instructions;
		hook_entries[id] = std::move(attach_entry);
		for (const auto &kv : hook_entries) {
			if (kv.second.kernel_name == kernel_name)
				programs.emplace_back(kv.second.probe_type,
						      kv.second.instructions);
		}
	}
	auto rollback_hook_entry = [&]() {
		std::lock_guard<std::mutex> guard(hook_entries_mutex);
		hook_entries.erase(id);
	};
	SPDLOG_INFO("rocm_attach_impl: attach id {} -> kernel {} ({} probe(s))",
		    id, kernel_name, programs.size());

	// Step A: eBPF -> IR string per program (LLVM 18, in-process). Each
	// program gets a fresh VM; helper calls are emitted as
	// _bpf_helper_ext_NNNN declarations, so merging several IR modules is
	// collision-free (only the entry symbols differ, by probe type).
	std::vector<std::string> ir_strs;
	ir_strs.reserve(programs.size());
	for (size_t p = 0; p < programs.size(); p++) {
		const auto &prog_probe_type = programs[p].first;
		const auto &prog_instructions = programs[p].second;
		try {
			gprobe::llvmbpf_vm vm;
			vm.set_aot_target("amdgcn-amd-amdhsa");

			if (vm.load_code(prog_instructions.data(),
					 prog_instructions.size() *
						sizeof(ebpf_inst)) < 0) {
				SPDLOG_ERROR(
					"rocm_attach_impl: failed to load eBPF code: {}",
					vm.get_error_message());
				rollback_hook_entry();
				return -EINVAL;
			}

			for (int i = 0; i < 1000; i++) {
				vm.register_external_function(
					i, "helper_" + std::to_string(i),
					nullptr);
			}

			std::string ir_str = vm.get_llvm_module_ir(
				kernel_name, prog_probe_type);
			if (ir_str.empty()) {
				SPDLOG_ERROR(
					"rocm_attach_impl: IR generation failed: {}",
					vm.get_error_message());
				rollback_hook_entry();
				return -EFAULT;
			}
			SPDLOG_INFO(
				"rocm_attach_impl: probe {} IR size: {}",
				prog_probe_type, ir_str.size());
			ir_strs.push_back(std::move(ir_str));
		} catch (const std::exception &e) {
			SPDLOG_ERROR("rocm_attach_impl: IR generation failed: {}",
				     e.what());
			rollback_hook_entry();
			return -EFAULT;
		}
	}

	// Step B: write every IR string to its own temporary file
	std::vector<std::string> tmp_ir_files;
	auto cleanup_tmp_ir_files = [&tmp_ir_files]() {
		for (const auto &f : tmp_ir_files)
			unlink(f.c_str());
	};
	for (const auto &ir_str : ir_strs) {
		char tmp_ir[] = "/tmp/gprobe_ebpf_ir.XXXXXX";
		int tmp_ir_fd = mkstemp(tmp_ir);
		if (tmp_ir_fd < 0) {
			SPDLOG_ERROR("rocm_attach_impl: mkstemp(IR) failed");
			cleanup_tmp_ir_files();
			rollback_hook_entry();
			return -EFAULT;
		}
		(void)!write(tmp_ir_fd, ir_str.data(), ir_str.size());
		fsync(tmp_ir_fd);
		close(tmp_ir_fd);
		tmp_ir_files.push_back(tmp_ir);
	}

	char tmp_out[] = "/tmp/gprobe_hsaco.XXXXXX";
	int tmp_out_fd = mkstemp(tmp_out);
	if (tmp_out_fd < 0) {
		SPDLOG_ERROR("rocm_attach_impl: mkstemp(output) failed");
		cleanup_tmp_ir_files();
		rollback_hook_entry();
		return -EFAULT;
	}
	close(tmp_out_fd);

	const char *helper_path = get_default_helper_path();

	// Locate hip-pipeline-helper binary
	std::string hip_helper;
	const char *env_helper =
		std::getenv("GPROBE_HIP_PIPELINE_HELPER");
	if (env_helper && env_helper[0]) {
		hip_helper = env_helper;
	} else {
		hip_helper = DEFAULT_HIP_PIPELINE_HELPER;
	}

	// Step C-G: fork+exec hip-pipeline-helper (LLVM 23, isolated), passing
	// one --ir per probe. The helper dispatches probe insertion by the
	// entry-symbol prefix of each module, so no --probe-type is needed.
	std::vector<char *> args;
	args.push_back(const_cast<char *>(hip_helper.c_str()));
	args.push_back(const_cast<char *>("--hip"));
	args.push_back(const_cast<char *>(data.hip_source_path.c_str()));
	for (const auto &tmp_ir : tmp_ir_files) {
		args.push_back(const_cast<char *>("--ir"));
		args.push_back(const_cast<char *>(tmp_ir.c_str()));
	}
	args.push_back(const_cast<char *>("--helper"));
	args.push_back(const_cast<char *>(helper_path));
	args.push_back(const_cast<char *>("--kernel"));
	args.push_back(const_cast<char *>(kernel_name.c_str()));
	args.push_back(const_cast<char *>("--mcpu"));
	args.push_back(const_cast<char *>(mcpu.c_str()));
	args.push_back(const_cast<char *>("--output"));
	args.push_back(const_cast<char *>(tmp_out));
	args.push_back(nullptr);

	std::ostringstream cmd_desc;
	for (const auto *a : args) {
		if (a)
			cmd_desc << a << ' ';
	}
	SPDLOG_INFO("rocm_attach_impl: fork+exec {}", cmd_desc.str());

	pid_t pid = fork();
	if (pid < 0) {
		SPDLOG_ERROR("rocm_attach_impl: fork failed");
		cleanup_tmp_ir_files();
		unlink(tmp_out);
		rollback_hook_entry();
		return -EFAULT;
	}
	if (pid == 0) {
		unsetenv("LD_PRELOAD");
		unsetenv("GPROBE_LOG_OUTPUT");
		unsetenv("GPROBE_HIP_PIPELINE_HELPER");
		unsetenv("GPROBE_ROCM_HIP_SOURCE");
		unsetenv("GPROBE_ROCM_HELPER_PATH");
		unsetenv("SPDLOG_LEVEL");
		execvp(hip_helper.c_str(), args.data());
		_exit(127);
	}

	int status;
	waitpid(pid, &status, 0);
	cleanup_tmp_ir_files();

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		SPDLOG_ERROR(
			"rocm_attach_impl: hip-pipeline-helper failed (status={})",
			status);
		unlink(tmp_out);
		rollback_hook_entry();
		return -EFAULT;
	}

	// Read hsaco from output file
	std::ifstream hsaco_file(tmp_out, std::ios::binary);
	if (!hsaco_file.is_open()) {
		SPDLOG_ERROR(
			"rocm_attach_impl: cannot open hsaco output {}", tmp_out);
		unlink(tmp_out);
		rollback_hook_entry();
		return -EFAULT;
	}
	std::vector<uint8_t> hsaco_data((std::istreambuf_iterator<char>(
		hsaco_file)),
					std::istreambuf_iterator<char>());
	hsaco_file.close();
	unlink(tmp_out);

	if (hsaco_data.empty()) {
		SPDLOG_ERROR(
			"rocm_attach_impl: hsaco output is empty");
		rollback_hook_entry();
		return -EFAULT;
	}
	SPDLOG_INFO("rocm_attach_impl: hsaco loaded, {} bytes",
		    hsaco_data.size());

	// Step H: Load instrumented module
	hipModule_t instrumented_module;
	hipError_t result = hipModuleLoadData(&instrumented_module,
					      hsaco_data.data());
	if (result != hipSuccess) {
		SPDLOG_ERROR(
			"rocm_attach_impl: hipModuleLoadData failed: {}",
			hipGetErrorString(result));
		rollback_hook_entry();
		return -EFAULT;
	}

	// Step I: Copy constData + map_info to device
	hipDeviceptr_t constData_ptr = 0, map_info_ptr = 0;
	size_t constData_sz = 0, map_info_sz = 0;
	result = hipModuleGetGlobal(&constData_ptr, &constData_sz,
				    instrumented_module, "constData");
	if (result != hipSuccess) {
		SPDLOG_WARN(
			"rocm_attach_impl: failed to get constData global: {}",
			hipGetErrorString(result));
	}
	if (result == hipSuccess) {
		SPDLOG_INFO(
			"rocm_attach_impl: constData dev={:x} sz={} comm_shared_mem={:x}",
			(uintptr_t)constData_ptr, constData_sz,
			(uintptr_t)data.comm_shared_mem);
		auto me = hipMemcpyHtoD(constData_ptr,
					&data.comm_shared_mem,
					std::min(constData_sz,
						 sizeof(data.comm_shared_mem)));
		if (me != hipSuccess)
			SPDLOG_ERROR(
				"rocm_attach_impl: hipMemcpyHtoD(constData) failed: {}",
				hipGetErrorString(me));
	}

	result = hipModuleGetGlobal(&map_info_ptr, &map_info_sz,
				    instrumented_module, "map_info");
	if (result != hipSuccess) {
		SPDLOG_WARN(
			"rocm_attach_impl: failed to get map_info global: {}",
			hipGetErrorString(result));
	}
	if (result == hipSuccess) {
		auto copy_sz = std::min(map_info_sz,
				       data.map_basic_info.size() *
					       sizeof(MapBasicInfo));
		SPDLOG_INFO(
			"rocm_attach_impl: map_info dev={:x} sz={} copy_sz={}",
			(uintptr_t)map_info_ptr, map_info_sz, copy_sz);
		for (size_t i = 0; i < data.map_basic_info.size(); i++) {
			auto &mi = data.map_basic_info[i];
			if (mi.enabled)
				SPDLOG_INFO(
					"  map_info[{}] enabled k={} v={} type={} buf={:x}",
					i, mi.key_size, mi.value_size,
					mi.map_type,
					(uintptr_t)mi.extra_buffer);
		}
		auto me = hipMemcpyHtoD(map_info_ptr,
					data.map_basic_info.data(), copy_sz);
		if (me != hipSuccess)
			SPDLOG_ERROR(
				"rocm_attach_impl: hipMemcpyHtoD(map_info) failed: {}",
				hipGetErrorString(me));
	}
	SPDLOG_INFO(
		"rocm_attach_impl: copied constData and map_info to device");

	// Step J: Get hipFunction_t for the instrumented kernel
	hipFunction_t hip_func;
	result = hipModuleGetFunction(&hip_func, instrumented_module,
				      kernel_name.c_str());
	if (result != hipSuccess) {
		SPDLOG_ERROR(
			"rocm_attach_impl: hipModuleGetFunction({}) failed: {}",
			kernel_name, hipGetErrorString(result));
		(void)hipModuleUnload(instrumented_module);
		rollback_hook_entry();
		return -EFAULT;
	}

	// Step K: Record instrumented kernel entry. When an older instrumented
	// module exists, swap the entry first, drain in-flight launches (they
	// still hold the old hipFunction), and only then unload the old module.
	hipModule_t old_module = nullptr;
	auto old_it = instrumented_kernels.find(kernel_name);
	if (old_it != instrumented_kernels.end())
		old_module = old_it->second.hsaco_module;

	instrumented_kernel_entry entry;
	entry.kernel_name = kernel_name;
	entry.hsaco_module = instrumented_module;
	entry.hip_function = hip_func;
	entry.hsaco_data = std::move(hsaco_data);
	entry.ebpf_programs = programs;
	instrumented_kernels[kernel_name] = std::move(entry);
	record_kernel_function_name(hip_func, kernel_name);

	if (old_module) {
		wait_for_patched_launch_events(std::chrono::seconds(2));
		(void)hipModuleUnload(old_module);
		SPDLOG_INFO(
			"rocm_attach_impl: replaced instrumented kernel {} ({} probe(s) active)",
			kernel_name, programs.size());
	} else {
		SPDLOG_INFO("rocm_attach_impl: instrumented kernel {} ready",
			    kernel_name);
	}
	return id;
}

int rocm_attach_impl::detach_by_id(int id)
{
	bool last_entry;
	{
		std::lock_guard<std::mutex> guard(hook_entries_mutex);
		auto itr = hook_entries.find(id);
		if (itr == hook_entries.end()) {
			SPDLOG_WARN(
				"rocm_attach_impl: detach unknown id {}", id);
			return -ENOENT;
		}
		hook_entries.erase(itr);
		last_entry = hook_entries.empty();
		if (!last_entry) {
			// Simple mode (mirrors nv_attach_impl): keep the current
			// hsaco; the detached probe stays compiled in until the
			// last entry is detached.
			SPDLOG_INFO("rocm_attach_impl: detached id {}", id);
		}
	}
	if (last_entry) {
		SPDLOG_INFO(
			"rocm_attach_impl: last entry detached; disabling kernel launch replacement");
		enabled.store(false, std::memory_order_release);
		// Wait for in-flight patched kernels to complete before the
		// loader exits and tears down GPU IPC buffers.
		wait_for_patched_launch_events(std::chrono::seconds(2));
		clear_patched_state_for_next_session();
	}
	return 0;
}

void rocm_attach_impl::register_custom_helpers(
	ebpf_helper_register_callback register_callback)
{
	SPDLOG_DEBUG("rocm_attach_impl: register_custom_helpers");
}

void rocm_attach_impl::mirror_hip_memcpy_to_symbol(
	const void *symbol, const void *src, size_t count, size_t offset,
	int kind)
{
	if (!symbol || !src || count == 0)
		return;

	std::string var_name = rocm_lookup_variable_name(symbol);
	if (var_name.empty())
		return;

	SPDLOG_DEBUG(
		"rocm_attach_impl: mirroring hipMemcpyToSymbol('{}', count={}, offset={}, kind={})",
		var_name, count, offset, kind);

	void *dev_ptr = nullptr;
	size_t dev_sz = 0;
	{
		std::lock_guard<std::mutex> guard(patched_global_cache_mutex);
		auto itr = patched_global_by_name.find(var_name);
		if (itr != patched_global_by_name.end()) {
			dev_ptr = itr->second.first;
			dev_sz = itr->second.second;
		}
	}

	if (!dev_ptr) {
		for (const auto &[name, entry] :
		     get_instrumented_kernels()) {
			hipDeviceptr_t ptr = 0;
			size_t sz = 0;
			auto err = hipModuleGetGlobal(
				&ptr, &sz, entry.hsaco_module,
				var_name.c_str());
			if (err == hipSuccess) {
				dev_ptr = (void *)ptr;
				dev_sz = sz;
				std::lock_guard<std::mutex> guard(
					patched_global_cache_mutex);
				patched_global_by_name[var_name] =
					std::make_pair(dev_ptr, dev_sz);
				break;
			}
		}
	}

	if (!dev_ptr) {
		SPDLOG_DEBUG(
			"rocm_attach_impl: variable '{}' not found in any instrumented module",
			var_name);
		return;
	}

	if (offset >= dev_sz) {
		SPDLOG_WARN(
			"rocm_attach_impl: offset {} exceeds size {} for variable '{}'",
			offset, dev_sz, var_name);
		return;
	}
	size_t bytes_to_copy = std::min(count, dev_sz - offset);

	hipError_t err;
	if (kind == (int)hipMemcpyHostToDevice ||
	    kind == (int)hipMemcpyDefault) {
		err = hipMemcpyHtoD(
			(hipDeviceptr_t)((uintptr_t)dev_ptr + offset),
			src, bytes_to_copy);
	} else if (kind == (int)hipMemcpyDeviceToDevice) {
		err = hipMemcpyDtoD(
			(hipDeviceptr_t)((uintptr_t)dev_ptr + offset),
			(hipDeviceptr_t)src, bytes_to_copy);
	} else {
		SPDLOG_DEBUG(
			"rocm_attach_impl: unsupported kind {} for variable '{}'",
			kind, var_name);
		return;
	}

	if (err != hipSuccess) {
		SPDLOG_WARN(
			"rocm_attach_impl: failed to mirror symbol '{}' write: {}",
			var_name, hipGetErrorString(err));
	}
}

bool rocm_attach_impl::mirror_hip_memcpy_from_symbol(
	void *dst, const void *symbol, size_t count, size_t offset, int kind)
{
	if (!dst || !symbol || count == 0)
		return false;

	std::string var_name = rocm_lookup_variable_name(symbol);
	if (var_name.empty())
		return false;

	SPDLOG_DEBUG(
		"rocm_attach_impl: mirroring hipMemcpyFromSymbol('{}', count={}, offset={}, kind={})",
		var_name, count, offset, kind);

	void *dev_ptr = nullptr;
	size_t dev_sz = 0;
	{
		std::lock_guard<std::mutex> guard(patched_global_cache_mutex);
		auto itr = patched_global_by_name.find(var_name);
		if (itr != patched_global_by_name.end()) {
			dev_ptr = itr->second.first;
			dev_sz = itr->second.second;
		}
	}

	if (!dev_ptr) {
		for (const auto &[name, entry] :
		     get_instrumented_kernels()) {
			hipDeviceptr_t ptr = 0;
			size_t sz = 0;
			auto err = hipModuleGetGlobal(
				&ptr, &sz, entry.hsaco_module,
				var_name.c_str());
			if (err == hipSuccess) {
				dev_ptr = (void *)ptr;
				dev_sz = sz;
				std::lock_guard<std::mutex> guard(
					patched_global_cache_mutex);
				patched_global_by_name[var_name] =
					std::make_pair(dev_ptr, dev_sz);
				break;
			}
		}
	}

	if (!dev_ptr) {
		SPDLOG_DEBUG(
			"rocm_attach_impl: variable '{}' not found in any instrumented module for FromSymbol",
			var_name);
		return false;
	}

	if (offset >= dev_sz) {
		SPDLOG_WARN(
			"rocm_attach_impl: offset {} exceeds size {} for variable '{}' in FromSymbol",
			offset, dev_sz, var_name);
		return false;
	}
	size_t bytes_to_copy = std::min(count, dev_sz - offset);

	hipError_t err;
	if (kind == (int)hipMemcpyDeviceToHost ||
	    kind == (int)hipMemcpyDefault) {
		err = hipMemcpyDtoH(
			dst,
			(hipDeviceptr_t)((uintptr_t)dev_ptr + offset),
			bytes_to_copy);
	} else if (kind == (int)hipMemcpyDeviceToDevice) {
		err = hipMemcpyDtoD(
			(hipDeviceptr_t)dst,
			(hipDeviceptr_t)((uintptr_t)dev_ptr + offset),
			bytes_to_copy);
	} else {
		SPDLOG_DEBUG(
			"rocm_attach_impl: unsupported kind {} for variable '{}' in FromSymbol",
			kind, var_name);
		return false;
	}

	if (err != hipSuccess) {
		SPDLOG_WARN(
			"rocm_attach_impl: failed to mirror symbol '{}' read: {}",
			var_name, hipGetErrorString(err));
		return false;
	}
	return true;
}

void rocm_attach_impl::record_kernel_function_name(
	hipFunction_t func, const std::string &name)
{
	if (!func || name.empty())
		return;
	std::lock_guard<std::mutex> guard(function_name_mutex);
	kernel_name_by_function[func] = name;
}

std::optional<std::string>
rocm_attach_impl::find_kernel_name_by_function(
	hipFunction_t func) const
{
	if (!func)
		return std::nullopt;
	std::lock_guard<std::mutex> guard(function_name_mutex);
	auto it = kernel_name_by_function.find(func);
	if (it == kernel_name_by_function.end())
		return std::nullopt;
	return it->second;
}

void rocm_attach_impl::record_patched_launch(hipStream_t stream)
{
	hipEvent_t ev = nullptr;
	if (hipEventCreateWithFlags(&ev, hipEventDisableTiming) !=
		    hipSuccess ||
	    !ev)
		return;
	if (hipEventRecord(ev, stream) != hipSuccess) {
		(void)hipEventDestroy(ev);
		return;
	}
	std::lock_guard<std::mutex> guard(launch_event_mutex);
	auto it = pending_launch_events_by_stream.find(stream);
	if (it != pending_launch_events_by_stream.end()) {
		if (it->second)
			(void)hipEventDestroy(it->second);
		it->second = ev;
	} else {
		pending_launch_events_by_stream.emplace(stream, ev);
	}
}

void rocm_attach_impl::wait_for_patched_launch_events(
	std::chrono::milliseconds timeout)
{
	auto deadline = std::chrono::steady_clock::now() + timeout;
	for (;;) {
		std::vector<std::pair<hipStream_t, hipEvent_t>> batch;
		{
			std::lock_guard<std::mutex> guard(
				launch_event_mutex);
			batch.reserve(
				pending_launch_events_by_stream.size());
			for (auto &kv :
			     pending_launch_events_by_stream)
				batch.emplace_back(kv.first, kv.second);
			pending_launch_events_by_stream.clear();
		}
		if (batch.empty())
			return;

		std::vector<std::pair<hipStream_t, hipEvent_t>> not_ready;
		not_ready.reserve(batch.size());
		for (auto &kv : batch) {
			hipEvent_t ev = kv.second;
			if (!ev)
				continue;
			auto st = hipEventQuery(ev);
			if (st == hipSuccess) {
				(void)hipEventDestroy(ev);
			} else if (st == hipErrorNotReady) {
				not_ready.emplace_back(kv.first, ev);
			} else {
				(void)hipEventDestroy(ev);
			}
		}
		if (not_ready.empty())
			return;
		if (std::chrono::steady_clock::now() >= deadline) {
			std::lock_guard<std::mutex> guard(
				launch_event_mutex);
			for (auto &kv : not_ready)
				pending_launch_events_by_stream[kv
								.first] =
					kv.second;
			SPDLOG_WARN(
				"rocm_attach_impl: detach timeout waiting for {} patched kernel event(s)",
				not_ready.size());
			return;
		}
		{
			std::lock_guard<std::mutex> guard(
				launch_event_mutex);
			for (auto &kv : not_ready)
				pending_launch_events_by_stream[kv
								.first] =
					kv.second;
		}
		std::this_thread::sleep_for(
			std::chrono::milliseconds(5));
	}
}

void rocm_attach_impl::clear_patched_state_for_next_session()
{
	for (auto &[name, entry] : instrumented_kernels) {
		if (entry.hsaco_module)
			(void)hipModuleUnload(entry.hsaco_module);
	}
	instrumented_kernels.clear();

	{
		std::lock_guard<std::mutex> guard(
			patched_global_cache_mutex);
		patched_global_by_name.clear();
	}
	{
		std::lock_guard<std::mutex> guard(
			function_name_mutex);
		kernel_name_by_function.clear();
	}
	{
		std::lock_guard<std::mutex> guard(
			launch_event_mutex);
		for (auto &kv :
		     pending_launch_events_by_stream) {
			if (kv.second)
				(void)hipEventDestroy(kv.second);
		}
		pending_launch_events_by_stream.clear();
	}

	rocm_clear_global_state();
}

} // namespace attach
} // namespace gprobe
