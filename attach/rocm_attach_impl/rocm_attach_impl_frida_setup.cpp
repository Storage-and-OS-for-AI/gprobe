#include "rocm_attach_impl.hpp"
#include "spdlog/spdlog.h"

#ifdef __has_attribute
#undef __has_attribute
#endif

#include <frida-gum.h>
#include <dlfcn.h>
#include <hip/hip_runtime.h>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <link.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace gprobe
{
namespace attach
{

static rocm_attach_impl *g_active_rocm_impl = nullptr;

using hipLaunchKernel_fn_t = hipError_t (*)(const void *, dim3, dim3,
					     void **, size_t, hipStream_t);
static hipLaunchKernel_fn_t original_hipLaunchKernel = nullptr;

using hipRegisterFunction_fn_t =
	void (*)(void **, const void *, char *, const char *, unsigned int,
		 uint3 *, uint3 *, dim3 *, dim3 *, int *);
static hipRegisterFunction_fn_t original_hipRegisterFunction = nullptr;

using hipRegisterVar_fn_t =
	void (*)(void **, void *, const char *, const char *, int,
		 size_t, int, int);
static hipRegisterVar_fn_t original_hipRegisterVar = nullptr;

using hipMemcpyToSymbol_fn_t =
	hipError_t (*)(const void *, const void *, size_t, size_t,
		       hipMemcpyKind);
static hipMemcpyToSymbol_fn_t original_hipMemcpyToSymbol = nullptr;

using hipMemcpyToSymbolAsync_fn_t =
	hipError_t (*)(const void *, const void *, size_t, size_t,
		       hipMemcpyKind, hipStream_t);
static hipMemcpyToSymbolAsync_fn_t original_hipMemcpyToSymbolAsync = nullptr;

using hipMemcpyFromSymbol_fn_t =
	hipError_t (*)(void *, const void *, size_t, size_t,
		       hipMemcpyKind);
static hipMemcpyFromSymbol_fn_t original_hipMemcpyFromSymbol = nullptr;

using hipMemcpyFromSymbolAsync_fn_t =
	hipError_t (*)(void *, const void *, size_t, size_t,
		       hipMemcpyKind, hipStream_t);
static hipMemcpyFromSymbolAsync_fn_t original_hipMemcpyFromSymbolAsync = nullptr;

using hipModuleGetFunction_fn_t =
	hipError_t (*)(hipFunction_t *, hipModule_t, const char *);
static hipModuleGetFunction_fn_t original_hipModuleGetFunction = nullptr;

using hipModuleLaunchKernel_fn_t =
	hipError_t (*)(hipFunction_t, unsigned int, unsigned int,
		       unsigned int, unsigned int, unsigned int,
		       unsigned int, unsigned int, hipStream_t, void **,
		       void **);
static hipModuleLaunchKernel_fn_t original_hipModuleLaunchKernel = nullptr;

using hipGraphAddKernelNode_fn_t =
	hipError_t (*)(hipGraphNode_t *, hipGraph_t, const hipGraphNode_t *,
		       size_t, const hipKernelNodeParams *);
static hipGraphAddKernelNode_fn_t original_hipGraphAddKernelNode = nullptr;

using hipGraphExecKernelNodeSetParams_fn_t =
	hipError_t (*)(hipGraphExec_t, hipGraphNode_t,
		       const hipKernelNodeParams *);
static hipGraphExecKernelNodeSetParams_fn_t
	original_hipGraphExecKernelNodeSetParams = nullptr;

using hipGraphKernelNodeSetParams_fn_t =
	hipError_t (*)(hipGraphNode_t, const hipKernelNodeParams *);
static hipGraphKernelNodeSetParams_fn_t
	original_hipGraphKernelNodeSetParams = nullptr;

static std::unordered_map<const void *, std::string> g_kernel_stub_names;
static std::mutex g_kernel_stub_mutex;

static std::unordered_map<const void *, std::string> g_variable_stub_names;
static std::mutex g_variable_stub_mutex;

static std::mutex g_elf_resolved_mutex;
static std::unordered_map<const void *, std::string> g_elf_resolved_names;

static bool parse_module_symbols(
	uintptr_t base, const char *path,
	std::vector<std::pair<uintptr_t, std::string>> &out)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;
	struct stat st;
	if (fstat(fd, &st) != 0) {
		close(fd);
		return false;
	}
	size_t size = (size_t)st.st_size;
	if (size < sizeof(Elf64_Ehdr)) {
		close(fd);
		return false;
	}
	void *map = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED)
		return false;

	const auto *ehdr = (const Elf64_Ehdr *)map;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_shoff == 0 || ehdr->e_shentsize == 0) {
		munmap(map, size);
		return false;
	}

	const auto *shdrs =
		(const Elf64_Shdr *)((const char *)map + ehdr->e_shoff);
	int symtab_idx = -1;
	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (shdrs[i].sh_type == SHT_SYMTAB) {
			symtab_idx = i;
			break;
		}
	}
	if (symtab_idx < 0) {
		for (int i = 0; i < ehdr->e_shnum; i++) {
			if (shdrs[i].sh_type == SHT_DYNSYM) {
				symtab_idx = i;
				break;
			}
		}
	}
	if (symtab_idx < 0 || (size_t)shdrs[symtab_idx].sh_link >=
					   (size_t)ehdr->e_shnum) {
		munmap(map, size);
		return false;
	}

	const auto &sym_sh = shdrs[symtab_idx];
	const char *strtab =
		(const char *)map + shdrs[sym_sh.sh_link].sh_offset;
	const auto *syms = (const Elf64_Sym *)((const char *)map +
					       sym_sh.sh_offset);
	size_t count = sym_sh.sh_size / sizeof(Elf64_Sym);
	for (size_t i = 0; i < count; i++) {
		uint8_t type = ELF64_ST_TYPE(syms[i].st_info);
		if (type != STT_FUNC && type != STT_OBJECT)
			continue;
		if (syms[i].st_shndx == SHN_UNDEF ||
		    syms[i].st_name == 0 || syms[i].st_value == 0)
			continue;
		uintptr_t addr = base + (uintptr_t)syms[i].st_value;
		out.emplace_back(addr,
				 std::string(strtab + syms[i].st_name));
	}
	munmap(map, size);
	return !out.empty();
}

struct elf_lookup_arg {
	uintptr_t target;
	bool found = false;
	uintptr_t base = 0;
	std::string path;
};

static int elf_lookup_cb(struct dl_phdr_info *info, size_t, void *data)
{
	auto *arg = (elf_lookup_arg *)data;
	uintptr_t bias = (uintptr_t)info->dlpi_addr;
	uintptr_t lo = 0, hi = 0;
	for (int i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type != PT_LOAD)
			continue;
		uintptr_t v = bias + (uintptr_t)info->dlpi_phdr[i].p_vaddr;
		uintptr_t e = v + info->dlpi_phdr[i].p_memsz;
		if (lo == 0 || v < lo)
			lo = v;
		if (e > hi)
			hi = e;
	}
	if (arg->target < lo || arg->target >= hi)
		return 0;
	arg->found = true;
	arg->base = bias;
	arg->path = (info->dlpi_name != nullptr &&
		     info->dlpi_name[0] != '\0')
			    ? info->dlpi_name
			    : "/proc/self/exe";
	return 1;
}

static std::string
resolve_kernel_name_from_elf(const void *func)
{
	elf_lookup_arg arg;
	arg.target = (uintptr_t)func;
	dl_iterate_phdr(elf_lookup_cb, &arg);
	if (!arg.found)
		return "";

	std::vector<std::pair<uintptr_t, std::string>> syms;
	if (!parse_module_symbols(arg.base, arg.path.c_str(), syms))
		return "";
	for (const auto &[addr, name] : syms) {
		if (addr == (uintptr_t)func)
			return name;
	}
	return "";
}

static std::string rocm_lookup_kernel_name(const void *func)
{
	{
		std::lock_guard<std::mutex> lock(g_kernel_stub_mutex);
		auto itr = g_kernel_stub_names.find(func);
		if (itr != g_kernel_stub_names.end())
			return itr->second;
	}
	{
		std::lock_guard<std::mutex> lock(g_elf_resolved_mutex);
		auto itr = g_elf_resolved_names.find(func);
		if (itr != g_elf_resolved_names.end())
			return itr->second;
	}

	std::string name = resolve_kernel_name_from_elf(func);
	{
		std::lock_guard<std::mutex> lock(g_elf_resolved_mutex);
		g_elf_resolved_names[func] = name;
	}
	return name;
}

std::string rocm_lookup_variable_name(const void *symbol)
{
	{
		std::lock_guard<std::mutex> lock(g_variable_stub_mutex);
		auto itr = g_variable_stub_names.find(symbol);
		if (itr != g_variable_stub_names.end())
			return itr->second;
	}

	Dl_info info{};
	if (dladdr((void *)symbol, &info) != 0 &&
	    info.dli_sname != nullptr && info.dli_sname[0] != '\0') {
		std::string name(info.dli_sname);
		std::lock_guard<std::mutex> lock(g_variable_stub_mutex);
		g_variable_stub_names[symbol] = name;
		return name;
	}

	std::string name = resolve_kernel_name_from_elf(symbol);
	if (!name.empty()) {
		std::lock_guard<std::mutex> lock(g_variable_stub_mutex);
		g_variable_stub_names[symbol] = name;
	}
	return name;
}

extern "C" void rocm__hipRegisterFunction(
	void **modules, const void *hostFunction, char *deviceFunction,
	const char *deviceName, unsigned int threadLimit, uint3 *tid,
	uint3 *bid, dim3 *blockDim, dim3 *gridDim, int *wSize)
{
	if (hostFunction != nullptr && deviceFunction != nullptr) {
		std::lock_guard<std::mutex> lock(g_kernel_stub_mutex);
		g_kernel_stub_names[hostFunction] = deviceFunction;
		SPDLOG_DEBUG(
			"Registered HIP kernel stub {} -> '{}'",
			(void *)hostFunction, deviceFunction);
	}
	if (original_hipRegisterFunction) {
		original_hipRegisterFunction(modules, hostFunction,
					    deviceFunction, deviceName,
					    threadLimit, tid, bid, blockDim,
					    gridDim, wSize);
	}
}

extern "C" hipError_t
rocm__hipLaunchKernel(const void *func, dim3 gridDim, dim3 blockDim,
		      void **args, size_t sharedMem, hipStream_t stream)
{
	auto forward = [&]() -> hipError_t {
		return original_hipLaunchKernel
			       ? original_hipLaunchKernel(func, gridDim,
							  blockDim, args,
							  sharedMem, stream)
			       : hipLaunchKernel(func, gridDim, blockDim, args,
						 sharedMem, stream);
	};

	if (!g_active_rocm_impl || !g_active_rocm_impl->is_enabled())
		return forward();

	std::string kernel_name = rocm_lookup_kernel_name(func);
	if (kernel_name.empty()) {
		SPDLOG_DEBUG(
			"No registered HIP kernel name for func {}, bypassing",
			(void *)func);
		return forward();
	}

	auto hip_func =
		g_active_rocm_impl->find_instrumented_hip_function(
			kernel_name);
	if (!hip_func) {
		return forward();
	}

	SPDLOG_DEBUG(
		"Redirecting hipLaunchKernel({}) -> instrumented kernel",
		kernel_name);

	hipError_t err = hipModuleLaunchKernel(
		*hip_func, gridDim.x, gridDim.y, gridDim.z, blockDim.x,
		blockDim.y, blockDim.z, sharedMem, stream, args, nullptr);
	if (err != hipSuccess) {
		SPDLOG_ERROR(
			"Failed to launch instrumented kernel {}: {}, falling back to original",
			kernel_name, hipGetErrorString(err));
		return forward();
	}
	g_active_rocm_impl->record_patched_launch(stream);
	return hipSuccess;
}

extern "C" void rocm__hipRegisterVar(
	void **fatbinHandle, void *hostVar, const char *deviceName,
	const char *hostName, int ext, size_t size, int constant,
	int global)
{
	if (hostVar != nullptr && deviceName != nullptr) {
		std::lock_guard<std::mutex> lock(g_variable_stub_mutex);
		g_variable_stub_names[hostVar] = deviceName;
		SPDLOG_DEBUG(
			"Registered HIP variable {} -> '{}'",
			hostVar, deviceName);
	}
	if (original_hipRegisterVar) {
		original_hipRegisterVar(fatbinHandle, hostVar, deviceName,
					hostName, ext, size, constant,
					global);
	}
}

extern "C" hipError_t rocm__hipMemcpyToSymbol(
	const void *symbol, const void *src, size_t count, size_t offset,
	hipMemcpyKind kind)
{
	auto original = [&]() -> hipError_t {
		return original_hipMemcpyToSymbol
			       ? original_hipMemcpyToSymbol(symbol, src, count,
							    offset, kind)
			       : hipMemcpyToSymbol(symbol, src, count, offset,
						   kind);
	};
	auto err = original();
	if (g_active_rocm_impl && g_active_rocm_impl->is_enabled()) {
		g_active_rocm_impl->mirror_hip_memcpy_to_symbol(
			symbol, src, count, offset, (int)kind);
	}
	return err;
}

extern "C" hipError_t rocm__hipMemcpyToSymbolAsync(
	const void *symbol, const void *src, size_t count, size_t offset,
	hipMemcpyKind kind, hipStream_t stream)
{
	auto original = [&]() -> hipError_t {
		return original_hipMemcpyToSymbolAsync
			       ? original_hipMemcpyToSymbolAsync(symbol, src,
								 count, offset,
								 kind, stream)
			       : hipMemcpyToSymbolAsync(symbol, src, count,
							offset, kind, stream);
	};
	auto err = original();
	if (g_active_rocm_impl && g_active_rocm_impl->is_enabled()) {
		g_active_rocm_impl->mirror_hip_memcpy_to_symbol(
			symbol, src, count, offset, (int)kind);
	}
	return err;
}

extern "C" hipError_t rocm__hipMemcpyFromSymbol(
	void *dst, const void *symbol, size_t count, size_t offset,
	hipMemcpyKind kind)
{
	auto original = [&]() -> hipError_t {
		return original_hipMemcpyFromSymbol
			       ? original_hipMemcpyFromSymbol(dst, symbol,
							     count, offset,
							     kind)
			       : hipMemcpyFromSymbol(dst, symbol, count,
						     offset, kind);
	};
	if (!g_active_rocm_impl || !g_active_rocm_impl->is_enabled())
		return original();
	if (g_active_rocm_impl->mirror_hip_memcpy_from_symbol(
		    dst, symbol, count, offset, (int)kind))
		return hipSuccess;
	return original();
}

extern "C" hipError_t rocm__hipMemcpyFromSymbolAsync(
	void *dst, const void *symbol, size_t count, size_t offset,
	hipMemcpyKind kind, hipStream_t stream)
{
	auto original = [&]() -> hipError_t {
		return original_hipMemcpyFromSymbolAsync
			       ? original_hipMemcpyFromSymbolAsync(
				     dst, symbol, count, offset, kind, stream)
			       : hipMemcpyFromSymbolAsync(dst, symbol, count,
							 offset, kind,
							 stream);
	};
	if (!g_active_rocm_impl || !g_active_rocm_impl->is_enabled())
		return original();
	if (g_active_rocm_impl->mirror_hip_memcpy_from_symbol(
		    dst, symbol, count, offset, (int)kind))
		return hipSuccess;
	return original();
}

extern "C" hipError_t rocm__hipModuleGetFunction(
	hipFunction_t *function, hipModule_t module, const char *kname)
{
	auto err = original_hipModuleGetFunction
			   ? original_hipModuleGetFunction(function, module,
							   kname)
			   : hipModuleGetFunction(function, module, kname);
	if (err == hipSuccess && g_active_rocm_impl &&
	    g_active_rocm_impl->is_enabled() && function && *function &&
	    kname && kname[0]) {
		g_active_rocm_impl->record_kernel_function_name(*function,
								kname);
	}
	return err;
}

extern "C" hipError_t rocm__hipModuleLaunchKernel(
	hipFunction_t f, unsigned int gridDimX, unsigned int gridDimY,
	unsigned int gridDimZ, unsigned int blockDimX,
	unsigned int blockDimY, unsigned int blockDimZ,
	unsigned int sharedMemBytes, hipStream_t stream,
	void **kernelParams, void **extra)
{
	auto original = [&]() -> hipError_t {
		return original_hipModuleLaunchKernel
			       ? original_hipModuleLaunchKernel(
				 f, gridDimX, gridDimY, gridDimZ, blockDimX,
				 blockDimY, blockDimZ, sharedMemBytes,
				 stream, kernelParams, extra)
			       : hipModuleLaunchKernel(
				 f, gridDimX, gridDimY, gridDimZ, blockDimX,
				 blockDimY, blockDimZ, sharedMemBytes,
				 stream, kernelParams, extra);
	};
	if (!g_active_rocm_impl || !g_active_rocm_impl->is_enabled())
		return original();
	auto name =
		g_active_rocm_impl->find_kernel_name_by_function(f);
	if (name) {
		auto instrumented =
			g_active_rocm_impl->find_instrumented_hip_function(
				*name);
		if (instrumented && *instrumented != f) {
			f = *instrumented;
			g_active_rocm_impl->record_patched_launch(stream);
		}
	}
	return original();
}

static const hipKernelNodeParams *
rocm_graph_maybe_patch_kernel_node_params(
	rocm_attach_impl &impl, const hipKernelNodeParams *params,
	hipKernelNodeParams &patched)
{
	if (!params || !params->func)
		return params;
	auto name = impl.find_kernel_name_by_function(
		(hipFunction_t)params->func);
	if (!name)
		return params;
	auto instrumented =
		impl.find_instrumented_hip_function(*name);
	if (!instrumented)
		return params;
	patched = *params;
	patched.func = (void *)*instrumented;
	return &patched;
}

extern "C" hipError_t rocm__hipGraphAddKernelNode(
	hipGraphNode_t *pGraphNode, hipGraph_t graph,
	const hipGraphNode_t *pDependencies, size_t numDependencies,
	const hipKernelNodeParams *pNodeParams)
{
	auto original = [&](hipGraphNode_t *pGraphNode, hipGraph_t graph,
			    const hipGraphNode_t *pDependencies,
			    size_t numDependencies,
			    const hipKernelNodeParams *pNodeParams) -> hipError_t {
		return original_hipGraphAddKernelNode
			       ? original_hipGraphAddKernelNode(
				 pGraphNode, graph, pDependencies,
				 numDependencies, pNodeParams)
			       : hipGraphAddKernelNode(
				 pGraphNode, graph, pDependencies,
				 numDependencies, pNodeParams);
	};
	if (!g_active_rocm_impl || !g_active_rocm_impl->is_enabled())
		return original(pGraphNode, graph, pDependencies,
				numDependencies, pNodeParams);
	hipKernelNodeParams patched;
	auto params = rocm_graph_maybe_patch_kernel_node_params(
		*g_active_rocm_impl, pNodeParams, patched);
	return original(pGraphNode, graph, pDependencies, numDependencies,
			params);
}

extern "C" hipError_t rocm__hipGraphExecKernelNodeSetParams(
	hipGraphExec_t hGraphExec, hipGraphNode_t node,
	const hipKernelNodeParams *pNodeParams)
{
	auto original = [&](hipGraphExec_t hGraphExec, hipGraphNode_t node,
			    const hipKernelNodeParams *pNodeParams)
				    -> hipError_t {
		return original_hipGraphExecKernelNodeSetParams
			       ? original_hipGraphExecKernelNodeSetParams(
				 hGraphExec, node, pNodeParams)
			       : hipGraphExecKernelNodeSetParams(hGraphExec,
								 node,
								 pNodeParams);
	};
	if (!g_active_rocm_impl || !g_active_rocm_impl->is_enabled())
		return original(hGraphExec, node, pNodeParams);
	hipKernelNodeParams patched;
	auto params = rocm_graph_maybe_patch_kernel_node_params(
		*g_active_rocm_impl, pNodeParams, patched);
	return original(hGraphExec, node, params);
}

extern "C" hipError_t rocm__hipGraphKernelNodeSetParams(
	hipGraphNode_t node, const hipKernelNodeParams *pNodeParams)
{
	auto original = [&](hipGraphNode_t node,
			    const hipKernelNodeParams *pNodeParams)
				    -> hipError_t {
		return original_hipGraphKernelNodeSetParams
			       ? original_hipGraphKernelNodeSetParams(node,
								      pNodeParams)
			       : hipGraphKernelNodeSetParams(node,
							     pNodeParams);
	};
	if (!g_active_rocm_impl || !g_active_rocm_impl->is_enabled())
		return original(node, pNodeParams);
	hipKernelNodeParams patched;
	auto params = rocm_graph_maybe_patch_kernel_node_params(
		*g_active_rocm_impl, pNodeParams, patched);
	return original(node, params);
}

void rocm_clear_global_state()
{
	{
		std::lock_guard<std::mutex> lock(g_kernel_stub_mutex);
		g_kernel_stub_names.clear();
	}
	{
		std::lock_guard<std::mutex> lock(g_variable_stub_mutex);
		g_variable_stub_names.clear();
	}
	{
		std::lock_guard<std::mutex> lock(g_elf_resolved_mutex);
		g_elf_resolved_names.clear();
	}
}

void rocm_attach_impl_setup_frida_hooks(rocm_attach_impl *impl)
{
	gum_init_embedded();
	auto interceptor = gum_interceptor_obtain();
	if (!interceptor) {
		SPDLOG_ERROR(
			"rocm_attach_impl: failed to obtain Frida interceptor");
		return;
	}
	impl->frida_interceptor = interceptor;

	gum_interceptor_begin_transaction(interceptor);

	void *hip_launch_kernel_addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr, "hipLaunchKernel"));
	if (hip_launch_kernel_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor, hip_launch_kernel_addr,
			(gpointer)&rocm__hipLaunchKernel, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipLaunchKernel =
				(hipLaunchKernel_fn_t)original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced hipLaunchKernel");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace hipLaunchKernel: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: hipLaunchKernel symbol not found");
	}

	void *hip_register_function_addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr,
					       "__hipRegisterFunction"));
	if (hip_register_function_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor, hip_register_function_addr,
			(gpointer)&rocm__hipRegisterFunction, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipRegisterFunction =
				(hipRegisterFunction_fn_t)original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced __hipRegisterFunction");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace __hipRegisterFunction: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: __hipRegisterFunction symbol not found");
	}

	void *hip_register_var_addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr,
					       "__hipRegisterVar"));
	if (hip_register_var_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor, hip_register_var_addr,
			(gpointer)&rocm__hipRegisterVar, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipRegisterVar =
				(hipRegisterVar_fn_t)original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced __hipRegisterVar");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace __hipRegisterVar: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: __hipRegisterVar symbol not found");
	}

	void *hip_memcpy_to_symbol_addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr,
					       "hipMemcpyToSymbol"));
	if (hip_memcpy_to_symbol_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor, hip_memcpy_to_symbol_addr,
			(gpointer)&rocm__hipMemcpyToSymbol, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipMemcpyToSymbol =
				(hipMemcpyToSymbol_fn_t)original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced hipMemcpyToSymbol");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace hipMemcpyToSymbol: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: hipMemcpyToSymbol symbol not found");
	}

	void *hip_memcpy_to_symbol_async_addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr,
					       "hipMemcpyToSymbolAsync"));
	if (hip_memcpy_to_symbol_async_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor, hip_memcpy_to_symbol_async_addr,
			(gpointer)&rocm__hipMemcpyToSymbolAsync, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipMemcpyToSymbolAsync =
				(hipMemcpyToSymbolAsync_fn_t)original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced hipMemcpyToSymbolAsync");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace hipMemcpyToSymbolAsync: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: hipMemcpyToSymbolAsync symbol not found");
	}

	void *hip_memcpy_from_symbol_addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr,
					       "hipMemcpyFromSymbol"));
	if (hip_memcpy_from_symbol_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor, hip_memcpy_from_symbol_addr,
			(gpointer)&rocm__hipMemcpyFromSymbol, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipMemcpyFromSymbol =
				(hipMemcpyFromSymbol_fn_t)original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced hipMemcpyFromSymbol");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace hipMemcpyFromSymbol: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: hipMemcpyFromSymbol symbol not found");
	}

	void *hip_memcpy_from_symbol_async_addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr,
					       "hipMemcpyFromSymbolAsync"));
	if (hip_memcpy_from_symbol_async_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor, hip_memcpy_from_symbol_async_addr,
			(gpointer)&rocm__hipMemcpyFromSymbolAsync, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipMemcpyFromSymbolAsync =
				(hipMemcpyFromSymbolAsync_fn_t)original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced hipMemcpyFromSymbolAsync");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace hipMemcpyFromSymbolAsync: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: hipMemcpyFromSymbolAsync symbol not found");
	}

	void *hip_module_get_function_addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr,
					       "hipModuleGetFunction"));
	if (hip_module_get_function_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor, hip_module_get_function_addr,
			(gpointer)&rocm__hipModuleGetFunction, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipModuleGetFunction =
				(hipModuleGetFunction_fn_t)original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced hipModuleGetFunction");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace hipModuleGetFunction: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: hipModuleGetFunction symbol not found");
	}

	void *hip_module_launch_kernel_addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr,
					       "hipModuleLaunchKernel"));
	if (hip_module_launch_kernel_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor, hip_module_launch_kernel_addr,
			(gpointer)&rocm__hipModuleLaunchKernel, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipModuleLaunchKernel =
				(hipModuleLaunchKernel_fn_t)original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced hipModuleLaunchKernel");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace hipModuleLaunchKernel: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: hipModuleLaunchKernel symbol not found");
	}

	void *hip_graph_add_kernel_node_addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr,
					       "hipGraphAddKernelNode"));
	if (hip_graph_add_kernel_node_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor, hip_graph_add_kernel_node_addr,
			(gpointer)&rocm__hipGraphAddKernelNode, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipGraphAddKernelNode =
				(hipGraphAddKernelNode_fn_t)original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced hipGraphAddKernelNode");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace hipGraphAddKernelNode: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: hipGraphAddKernelNode symbol not found");
	}

	void *hip_graph_exec_kernel_node_set_params_addr =
		GSIZE_TO_POINTER(gum_module_find_export_by_name(
			nullptr, "hipGraphExecKernelNodeSetParams"));
	if (hip_graph_exec_kernel_node_set_params_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor,
			hip_graph_exec_kernel_node_set_params_addr,
			(gpointer)&rocm__hipGraphExecKernelNodeSetParams,
			nullptr, &original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipGraphExecKernelNodeSetParams =
				(hipGraphExecKernelNodeSetParams_fn_t)
					original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced hipGraphExecKernelNodeSetParams");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace hipGraphExecKernelNodeSetParams: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: hipGraphExecKernelNodeSetParams symbol not found");
	}

	void *hip_graph_kernel_node_set_params_addr =
		GSIZE_TO_POINTER(gum_module_find_export_by_name(
			nullptr, "hipGraphKernelNodeSetParams"));
	if (hip_graph_kernel_node_set_params_addr) {
		gpointer original_tmp = nullptr;
		auto err = gum_interceptor_replace(
			interceptor,
			hip_graph_kernel_node_set_params_addr,
			(gpointer)&rocm__hipGraphKernelNodeSetParams, nullptr,
			&original_tmp);
		if (err == GUM_REPLACE_OK) {
			original_hipGraphKernelNodeSetParams =
				(hipGraphKernelNodeSetParams_fn_t)
					original_tmp;
			SPDLOG_INFO(
				"rocm_attach_impl: replaced hipGraphKernelNodeSetParams");
		} else {
			SPDLOG_ERROR(
				"rocm_attach_impl: failed to replace hipGraphKernelNodeSetParams: {}",
				(int)err);
		}
	} else {
		SPDLOG_WARN(
			"rocm_attach_impl: hipGraphKernelNodeSetParams symbol not found");
	}

	gum_interceptor_end_transaction(interceptor);

	g_active_rocm_impl = impl;
}

} // namespace attach
} // namespace gprobe
