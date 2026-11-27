/* SPDX-License-Identifier: MIT
 *
 * MACA (MetaX) attach implementation — port of
 * attach/rocm_attach_impl/rocm_attach_impl.cpp (the ROCm version), with the
 * pipeline delegated to maca-pipeline-helper (vm/llvm-jit, LLVM-free) and
 * the module handled via the mcModule* driver-style API.
 */
#include "maca_attach_impl.hpp"
#include "maca_attach_private_data.hpp"
#include "spdlog/spdlog.h"
#include "src/maca_env_guard.hpp"
#include <llvmbpf.hpp>
#include <mc_runtime.h>
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
#include <elf.h>
#include <vector>

namespace gprobe
{
namespace attach
{

static std::string find_default_helper_path()
{
	const char *env = std::getenv("GPROBE_MACA_HELPER_PATH");
	if (env) {
		return std::string(env);
	}
	std::filesystem::path p = DEFAULT_MACA_HELPER_PATH;
	return p.string();
}

// Scan a MetaX device object's ELF symbol table for undefined references.
//
// `mxcc -x ir -input-is-device -device-obj` does not diagnose unresolved
// symbols: a trampoline missing a `_bpf_helper_ext_<id>` that the eBPF
// program calls still yields a zero-exit-status REL object, and
// mcModuleLoadData then rejects it with a bare mcErrorInvalidValue that names
// neither the symbol nor the trampoline. Resolve the ambiguity here instead.
//
// Returns the offending names. Empty when the object is fully resolved, and
// also when it is not a parseable little-endian ELF64 image: the MACA loader
// accepts raw bitcode too, which this inspector simply cannot judge.
static std::vector<std::string>
find_undefined_device_symbols(const std::vector<uint8_t> &obj)
{
	std::vector<std::string> undefined;
	if (obj.size() < sizeof(Elf64_Ehdr))
		return undefined;

	const uint8_t *const base = obj.data();
	const auto *ehdr = reinterpret_cast<const Elf64_Ehdr *>(base);
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
		return undefined;
	if (ehdr->e_shoff == 0 || ehdr->e_shentsize < sizeof(Elf64_Shdr) ||
	    ehdr->e_shnum == 0 || ehdr->e_shstrndx >= ehdr->e_shnum)
		return undefined;

	const auto section_at = [&](uint16_t idx) -> const Elf64_Shdr * {
		const uint64_t off =
			ehdr->e_shoff + (uint64_t)idx * ehdr->e_shentsize;
		if (off > obj.size() || off + sizeof(Elf64_Shdr) > obj.size())
			return nullptr;
		return reinterpret_cast<const Elf64_Shdr *>(base + off);
	};

	for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
		const auto *shdr = section_at(i);
		if (!shdr || shdr->sh_type != SHT_SYMTAB ||
		    shdr->sh_entsize < sizeof(Elf64_Sym))
			continue;
		const auto *strtab = section_at((uint16_t)shdr->sh_link);
		if (!strtab ||
		    shdr->sh_offset + shdr->sh_size > obj.size() ||
		    strtab->sh_offset + strtab->sh_size > obj.size())
			continue;

		const auto *syms = reinterpret_cast<const Elf64_Sym *>(
			base + shdr->sh_offset);
		const char *strs =
			reinterpret_cast<const char *>(base + strtab->sh_offset);
		const size_t strsz = (size_t)strtab->sh_size;
		const size_t count = (size_t)shdr->sh_size / sizeof(Elf64_Sym);

		for (size_t s = 0; s < count; s++) {
			const auto &sym = syms[s];
			if (sym.st_shndx != SHN_UNDEF || sym.st_name == 0 ||
			    sym.st_name >= strsz)
				continue;
			// Section and file symbols are metadata, not
			// references the loader has to satisfy.
			const auto type = ELF64_ST_TYPE(sym.st_info);
			if (type == STT_SECTION || type == STT_FILE)
				continue;
			undefined.emplace_back(
				strs + sym.st_name,
				strnlen(strs + sym.st_name, strsz - sym.st_name));
		}
	}
	return undefined;
}

maca_attach_impl::maca_attach_impl()
{
	maca_attach_impl_setup_frida_hooks(this);
	SPDLOG_INFO("maca_attach_impl: Frida hooks installed");
}

maca_attach_impl::~maca_attach_impl()
{
	gprobe::maca::maca_runtime_env_guard runtime_env_guard;
	for (auto &[name, entry] : instrumented_kernels) {
		if (entry.module) {
			(void)mcModuleUnload(entry.module);
		}
	}
	instrumented_kernels.clear();
}

bool maca_attach_impl::is_enabled() const noexcept
{
	return enabled.load(std::memory_order_acquire);
}

const char *maca_attach_impl::get_default_helper_path() const
{
	static std::string path = find_default_helper_path();
	return path.c_str();
}

std::optional<mcFunction_t>
maca_attach_impl::find_instrumented_kernel_function(
	const std::string &name) const
{
	auto it = instrumented_kernels.find(name);
	if (it != instrumented_kernels.end()) {
		return it->second.kernel_function;
	}
	return std::nullopt;
}

int maca_attach_impl::create_attach_with_ebpf_callback(
	ebpf_run_callback &&cb, const attach_private_data &private_data,
	int attach_type)
{
	auto &data =
		dynamic_cast<const maca_attach_private_data &>(private_data);

	SPDLOG_INFO("maca_attach_impl: creating attach for program {}",
		    data.program_name);

	if (data.func_names.empty()) {
		SPDLOG_ERROR("maca_attach_impl: no kernel names specified");
		return -EINVAL;
	}

	const auto &kernel_name = data.func_names[0];
	std::string mcpu = "xcore1000";
	const char *mcpu_env = std::getenv("GPROBE_MACA_MCPU");
	if (mcpu_env) {
		mcpu = mcpu_env;
	}

	std::string probe_type =
		(attach_type == ATTACH_MACA_RETPROBE) ? "kretprobe" :
							"kprobe";

	const int id = allocate_id();

	// Register the attach entry first, then derive the live set of probes
	// for this kernel from hook_entries: a regenerated module must contain
	// every active probe of the kernel (e.g. kprobe + kretprobe), and the
	// set must not include probes detached in between (detach does not
	// regenerate the module, so instrumented_kernel_entry.ebpf_programs is
	// only a snapshot of the last build).
	maca_ebpf_probe_programs programs;
	{
		std::lock_guard<std::mutex> guard(hook_entries_mutex);
		for (const auto &kv : hook_entries) {
			if (kv.second.kernel_name == kernel_name &&
			    kv.second.probe_type == probe_type) {
				SPDLOG_ERROR(
					"maca_attach_impl: a {} program is already attached to kernel {}",
					probe_type, kernel_name);
				return -EEXIST;
			}
		}
		maca_attach_entry attach_entry;
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
	SPDLOG_INFO("maca_attach_impl: attach id {} -> kernel {} ({} probe(s))",
		    id, kernel_name, programs.size());

	// Re-enable interception: the agent's auto-refresh cycle
	// (destroy_all_attach_links + re-instantiate) routes through
	// detach_by_id, which clears `enabled` when the last entry goes
	// away; a fresh attach must restore it or every hook silently
	// forwards to the original functions.
	enabled.store(true, std::memory_order_release);

	// Step A: eBPF -> IR string per program (LLVM, in-process). Each
	// program gets a fresh VM; helper calls are emitted as
	// _bpf_helper_ext_NNNN declarations, so merging several IR modules is
	// collision-free (only the entry symbols differ, by probe type).
	// The mxc-metax-macahca triple triggers the same GPU-mode IR
	// generation as amdgcn (alloca addrspace(5), flat ctx).
	std::vector<std::string> ir_strs;
	ir_strs.reserve(programs.size());
	for (size_t p = 0; p < programs.size(); p++) {
		const auto &prog_probe_type = programs[p].first;
		const auto &prog_instructions = programs[p].second;
		try {
			gprobe::llvmbpf_vm vm;
			vm.set_aot_target("mxc-metax-macahca");

			if (vm.load_code(prog_instructions.data(),
					 prog_instructions.size() *
						sizeof(ebpf_inst)) < 0) {
				SPDLOG_ERROR(
					"maca_attach_impl: failed to load eBPF code: {}",
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
					"maca_attach_impl: IR generation failed: {}",
					vm.get_error_message());
				rollback_hook_entry();
				return -EFAULT;
			}
			SPDLOG_INFO(
				"maca_attach_impl: probe {} IR size: {}",
				prog_probe_type, ir_str.size());
			ir_strs.push_back(std::move(ir_str));
		} catch (const std::exception &e) {
			SPDLOG_ERROR("maca_attach_impl: IR generation failed: {}",
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
			SPDLOG_ERROR("maca_attach_impl: mkstemp(IR) failed");
			cleanup_tmp_ir_files();
			rollback_hook_entry();
			return -EFAULT;
		}
		(void)!write(tmp_ir_fd, ir_str.data(), ir_str.size());
		fsync(tmp_ir_fd);
		close(tmp_ir_fd);
		tmp_ir_files.push_back(tmp_ir);
	}

	char tmp_out[] = "/tmp/gprobe_maca_obj.XXXXXX";
	int tmp_out_fd = mkstemp(tmp_out);
	if (tmp_out_fd < 0) {
		SPDLOG_ERROR("maca_attach_impl: mkstemp(output) failed");
		cleanup_tmp_ir_files();
		rollback_hook_entry();
		return -EFAULT;
	}
	close(tmp_out_fd);

	const char *helper_path = get_default_helper_path();

	// Locate maca-pipeline-helper binary (compiled-in default from the
	// build system; overridable via GPROBE_MACA_PIPELINE_HELPER).
	std::string maca_helper;
	const char *env_helper =
		std::getenv("GPROBE_MACA_PIPELINE_HELPER");
	if (env_helper && env_helper[0]) {
		maca_helper = env_helper;
	} else {
		maca_helper = DEFAULT_MACA_PIPELINE_HELPER;
	}

	// Step C-G: fork+exec maca-pipeline-helper (LLVM-free, isolated),
	// passing one --ir per probe. The helper dispatches probe insertion by
	// the entry-symbol prefix of each module, so no --probe-type is needed.
	std::vector<char *> args;
	args.push_back(const_cast<char *>(maca_helper.c_str()));
	args.push_back(const_cast<char *>("--maca"));
	args.push_back(const_cast<char *>(data.maca_source_path.c_str()));
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
	SPDLOG_INFO("maca_attach_impl: fork+exec {}", cmd_desc.str());

	pid_t pid = fork();
	if (pid < 0) {
		SPDLOG_ERROR("maca_attach_impl: fork failed");
		cleanup_tmp_ir_files();
		unlink(tmp_out);
		rollback_hook_entry();
		return -EFAULT;
	}
	if (pid == 0) {
		// Avoid re-running the agent constructor in the helper (flock
		// deadlock — the ROCm #18 lesson) and leaking debug knobs into
		// the child.
		unsetenv("LD_PRELOAD");
		unsetenv("GPROBE_LOG_OUTPUT");
		unsetenv("GPROBE_MACA_PIPELINE_HELPER");
		unsetenv("GPROBE_MACA_SOURCE");
		unsetenv("GPROBE_MACA_HELPER_PATH");
		unsetenv("GPROBE_MACA_MCPU");
		unsetenv("SPDLOG_LEVEL");
		execvp(maca_helper.c_str(), args.data());
		_exit(127);
	}

	int status;
	waitpid(pid, &status, 0);
	cleanup_tmp_ir_files();

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		SPDLOG_ERROR(
			"maca_attach_impl: maca-pipeline-helper failed (status={})",
			status);
		unlink(tmp_out);
		rollback_hook_entry();
		return -EFAULT;
	}

	// Read the device object from the output file
	std::ifstream obj_file(tmp_out, std::ios::binary);
	if (!obj_file.is_open()) {
		SPDLOG_ERROR(
			"maca_attach_impl: cannot open output {}", tmp_out);
		unlink(tmp_out);
		rollback_hook_entry();
		return -EFAULT;
	}
	std::vector<uint8_t> obj_data((std::istreambuf_iterator<char>(
		obj_file)),
				      std::istreambuf_iterator<char>());
	obj_file.close();
	unlink(tmp_out);

	if (obj_data.empty()) {
		SPDLOG_ERROR("maca_attach_impl: output is empty");
		rollback_hook_entry();
		return -EFAULT;
	}
	SPDLOG_INFO("maca_attach_impl: device object loaded, {} bytes",
		    obj_data.size());

	// Pre-flight: an object with unresolved symbols can never load, and
	// mcModuleLoadData would only report a generic mcErrorInvalidValue.
	if (auto undefined = find_undefined_device_symbols(obj_data);
	    !undefined.empty()) {
		std::ostringstream missing;
		for (const auto &name : undefined)
			missing << ' ' << name;
		SPDLOG_ERROR(
			"maca_attach_impl: device object has {} undefined symbol(s):{} — trampoline '{}' does not implement every _bpf_helper_ext_<id> the eBPF program calls; refusing to load",
			undefined.size(), missing.str(), helper_path);
		rollback_hook_entry();
		return -EFAULT;
	}

	// Step H: Load instrumented module. Every MACA runtime call below may
	// fork helper processes (mcModuleLoadData JIT-links via an mxcc
	// subprocess); the guard hides LD_PRELOAD from those children so they
	// do not re-enter this library's constructor (which would deadlock on
	// the shm flock the agent holds during attach).
	gprobe::maca::maca_runtime_env_guard runtime_env_guard;
	mcModule_t instrumented_module;
	mcError_t result = mcModuleLoadData(&instrumented_module,
					     obj_data.data());
	if (result != mcSuccess) {
		SPDLOG_ERROR(
			"maca_attach_impl: mcModuleLoadData failed: {}",
			mcGetErrorString(result));
		rollback_hook_entry();
		return -EFAULT;
	}

	// Step I: Copy constData + map_info to device
	mcDeviceptr_t constData_ptr = 0, map_info_ptr = 0;
	size_t constData_sz = 0, map_info_sz = 0;
	result = mcModuleGetGlobal(&constData_ptr, &constData_sz,
				   instrumented_module, "constData");
	if (result != mcSuccess) {
		SPDLOG_WARN(
			"maca_attach_impl: failed to get constData global: {}",
			mcGetErrorString(result));
	}
	if (result == mcSuccess) {
		SPDLOG_INFO(
			"maca_attach_impl: constData dev={:x} sz={} comm_shared_mem={:x}",
			(uintptr_t)constData_ptr, constData_sz,
			(uintptr_t)data.comm_shared_mem);
		auto me = mcMemcpyHtoD(constData_ptr,
					&data.comm_shared_mem,
					std::min(constData_sz,
						 sizeof(data.comm_shared_mem)));
		if (me != mcSuccess)
			SPDLOG_ERROR(
				"maca_attach_impl: mcMemcpyHtoD(constData) failed: {}",
				mcGetErrorString(me));
	}

	result = mcModuleGetGlobal(&map_info_ptr, &map_info_sz,
				   instrumented_module, "map_info");
	if (result != mcSuccess) {
		SPDLOG_WARN(
			"maca_attach_impl: failed to get map_info global: {}",
			mcGetErrorString(result));
	}
	if (result == mcSuccess) {
		auto copy_sz = std::min(map_info_sz,
				       data.map_basic_info.size() *
					       sizeof(MapBasicInfo));
		SPDLOG_INFO(
			"maca_attach_impl: map_info dev={:x} sz={} copy_sz={}",
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
		auto me = mcMemcpyHtoD(map_info_ptr,
				       data.map_basic_info.data(), copy_sz);
		if (me != mcSuccess)
			SPDLOG_ERROR(
				"maca_attach_impl: mcMemcpyHtoD(map_info) failed: {}",
				mcGetErrorString(me));
	}
	SPDLOG_INFO(
		"maca_attach_impl: copied constData and map_info to device");

	// Step J: Get mcFunction_t for the instrumented kernel
	mcFunction_t kernel_func;
	result = mcModuleGetFunction(&kernel_func, instrumented_module,
				     kernel_name.c_str());
	if (result != mcSuccess) {
		SPDLOG_ERROR(
			"maca_attach_impl: mcModuleGetFunction({}) failed: {}",
			kernel_name, mcGetErrorString(result));
		(void)mcModuleUnload(instrumented_module);
		rollback_hook_entry();
		return -EFAULT;
	}

	// Step K: Record instrumented kernel entry. When an older instrumented
	// module exists, swap the entry first, drain in-flight launches (they
	// still hold the old mcFunction), and only then unload the old module.
	mcModule_t old_module = nullptr;
	auto old_it = instrumented_kernels.find(kernel_name);
	if (old_it != instrumented_kernels.end())
		old_module = old_it->second.module;

	maca_instrumented_kernel_entry entry;
	entry.kernel_name = kernel_name;
	entry.module = instrumented_module;
	entry.kernel_function = kernel_func;
	entry.module_data = std::move(obj_data);
	entry.ebpf_programs = programs;
	instrumented_kernels[kernel_name] = std::move(entry);
	record_kernel_function_name(kernel_func, kernel_name);

	if (old_module) {
		wait_for_patched_launch_events(std::chrono::seconds(2));
		(void)mcModuleUnload(old_module);
		SPDLOG_INFO(
			"maca_attach_impl: replaced instrumented kernel {} ({} probe(s) active)",
			kernel_name, programs.size());
	} else {
		SPDLOG_INFO("maca_attach_impl: instrumented kernel {} ready",
			    kernel_name);
	}
	return id;
}

int maca_attach_impl::detach_by_id(int id)
{
	bool last_entry;
	{
		std::lock_guard<std::mutex> guard(hook_entries_mutex);
		auto itr = hook_entries.find(id);
		if (itr == hook_entries.end()) {
			SPDLOG_WARN(
				"maca_attach_impl: detach unknown id {}", id);
			return -ENOENT;
		}
		hook_entries.erase(itr);
		last_entry = hook_entries.empty();
		if (!last_entry) {
			// Simple mode (mirrors nv_attach_impl/rocm_attach_impl):
			// keep the current module; the detached probe stays
			// compiled in until the last entry is detached.
			SPDLOG_INFO("maca_attach_impl: detached id {}", id);
		}
	}
	if (last_entry) {
		SPDLOG_INFO(
			"maca_attach_impl: last entry detached; disabling kernel launch replacement");
		enabled.store(false, std::memory_order_release);
		// Wait for in-flight patched kernels to complete before the
		// loader exits and tears down GPU IPC buffers.
		wait_for_patched_launch_events(std::chrono::seconds(2));
		clear_patched_state_for_next_session();
	}
	return 0;
}

void maca_attach_impl::register_custom_helpers(
	ebpf_helper_register_callback register_callback)
{
	SPDLOG_DEBUG("maca_attach_impl: register_custom_helpers");
}

void maca_attach_impl::mirror_maca_memcpy_to_symbol(
	const void *symbol, const void *src, size_t count, size_t offset,
	int kind)
{
	if (!symbol || !src || count == 0)
		return;

	gprobe::maca::maca_runtime_env_guard runtime_env_guard;

	std::string var_name = maca_lookup_variable_name(symbol);
	if (var_name.empty())
		return;

	SPDLOG_DEBUG(
		"maca_attach_impl: mirroring mcMemcpyToSymbol('{}', count={}, offset={}, kind={})",
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
			mcDeviceptr_t ptr = 0;
			size_t sz = 0;
			auto err = mcModuleGetGlobal(
				&ptr, &sz, entry.module,
				var_name.c_str());
			if (err == mcSuccess) {
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
			"maca_attach_impl: variable '{}' not found in any instrumented module",
			var_name);
		return;
	}

	if (offset >= dev_sz) {
		SPDLOG_WARN(
			"maca_attach_impl: offset {} exceeds size {} for variable '{}'",
			offset, dev_sz, var_name);
		return;
	}
	size_t bytes_to_copy = std::min(count, dev_sz - offset);

	mcError_t err;
	if (kind == (int)mcMemcpyHostToDevice ||
	    kind == (int)mcMemcpyDefault) {
		err = mcMemcpyHtoD(
			(mcDeviceptr_t)((uintptr_t)dev_ptr + offset),
			src, bytes_to_copy);
	} else if (kind == (int)mcMemcpyDeviceToDevice) {
		err = mcMemcpyDtoD(
			(mcDeviceptr_t)((uintptr_t)dev_ptr + offset),
			(mcDeviceptr_t)src, bytes_to_copy);
	} else {
		SPDLOG_DEBUG(
			"maca_attach_impl: unsupported kind {} for variable '{}'",
			kind, var_name);
		return;
	}

	if (err != mcSuccess) {
		SPDLOG_WARN(
			"maca_attach_impl: failed to mirror symbol '{}' write: {}",
			var_name, mcGetErrorString(err));
	}
}

bool maca_attach_impl::mirror_maca_memcpy_from_symbol(
	void *dst, const void *symbol, size_t count, size_t offset, int kind)
{
	if (!dst || !symbol || count == 0)
		return false;

	gprobe::maca::maca_runtime_env_guard runtime_env_guard;

	std::string var_name = maca_lookup_variable_name(symbol);
	if (var_name.empty())
		return false;

	SPDLOG_DEBUG(
		"maca_attach_impl: mirroring mcMemcpyFromSymbol('{}', count={}, offset={}, kind={})",
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
			mcDeviceptr_t ptr = 0;
			size_t sz = 0;
			auto err = mcModuleGetGlobal(
				&ptr, &sz, entry.module,
				var_name.c_str());
			if (err == mcSuccess) {
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
			"maca_attach_impl: variable '{}' not found in any instrumented module for FromSymbol",
			var_name);
		return false;
	}

	if (offset >= dev_sz) {
		SPDLOG_WARN(
			"maca_attach_impl: offset {} exceeds size {} for variable '{}' in FromSymbol",
			offset, dev_sz, var_name);
		return false;
	}
	size_t bytes_to_copy = std::min(count, dev_sz - offset);

	mcError_t err;
	if (kind == (int)mcMemcpyDeviceToHost ||
	    kind == (int)mcMemcpyDefault) {
		err = mcMemcpyDtoH(
			dst,
			(mcDeviceptr_t)((uintptr_t)dev_ptr + offset),
			bytes_to_copy);
	} else if (kind == (int)mcMemcpyDeviceToDevice) {
		err = mcMemcpyDtoD(
			(mcDeviceptr_t)dst,
			(mcDeviceptr_t)((uintptr_t)dev_ptr + offset),
			bytes_to_copy);
	} else {
		SPDLOG_DEBUG(
			"maca_attach_impl: unsupported kind {} for variable '{}' in FromSymbol",
			kind, var_name);
		return false;
	}

	if (err != mcSuccess) {
		SPDLOG_WARN(
			"maca_attach_impl: failed to mirror symbol '{}' read: {}",
			var_name, mcGetErrorString(err));
		return false;
	}
	return true;
}

void maca_attach_impl::record_kernel_function_name(
	mcFunction_t func, const std::string &name)
{
	if (!func || name.empty())
		return;
	std::lock_guard<std::mutex> guard(function_name_mutex);
	kernel_name_by_function[func] = name;
}

std::optional<std::string>
maca_attach_impl::find_kernel_name_by_function(
	mcFunction_t func) const
{
	if (!func)
		return std::nullopt;
	std::lock_guard<std::mutex> guard(function_name_mutex);
	auto it = kernel_name_by_function.find(func);
	if (it == kernel_name_by_function.end())
		return std::nullopt;
	return it->second;
}

void maca_attach_impl::record_patched_launch(mcStream_t stream)
{
	gprobe::maca::maca_runtime_env_guard runtime_env_guard;
	mcEvent_t ev = nullptr;
	if (mcEventCreateWithFlags(&ev, mcEventDisableTiming) !=
		    mcSuccess ||
	    !ev)
		return;
	if (mcEventRecord(ev, stream) != mcSuccess) {
		(void)mcEventDestroy(ev);
		return;
	}
	std::lock_guard<std::mutex> guard(launch_event_mutex);
	auto it = pending_launch_events_by_stream.find(stream);
	if (it != pending_launch_events_by_stream.end()) {
		if (it->second)
			(void)mcEventDestroy(it->second);
		it->second = ev;
	} else {
		pending_launch_events_by_stream.emplace(stream, ev);
	}
}

void maca_attach_impl::wait_for_patched_launch_events(
	std::chrono::milliseconds timeout)
{
	gprobe::maca::maca_runtime_env_guard runtime_env_guard;
	auto deadline = std::chrono::steady_clock::now() + timeout;
	for (;;) {
		std::vector<std::pair<mcStream_t, mcEvent_t>> batch;
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

		std::vector<std::pair<mcStream_t, mcEvent_t>> not_ready;
		not_ready.reserve(batch.size());
		for (auto &kv : batch) {
			mcEvent_t ev = kv.second;
			if (!ev)
				continue;
			auto st = mcEventQuery(ev);
			if (st == mcSuccess) {
				(void)mcEventDestroy(ev);
			} else if (st == mcErrorNotReady) {
				not_ready.emplace_back(kv.first, ev);
			} else {
				(void)mcEventDestroy(ev);
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
				"maca_attach_impl: detach timeout waiting for {} patched kernel event(s)",
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

void maca_attach_impl::clear_patched_state_for_next_session()
{
	gprobe::maca::maca_runtime_env_guard runtime_env_guard;
	for (auto &[name, entry] : instrumented_kernels) {
		if (entry.module)
			(void)mcModuleUnload(entry.module);
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
				(void)mcEventDestroy(kv.second);
		}
		pending_launch_events_by_stream.clear();
	}

	maca_clear_global_state();
}

} // namespace attach
} // namespace gprobe
