/* SPDX-License-Identifier: MIT
 *
 * MACA (MetaX) Frida hook set — port of
 * attach/rocm_attach_impl/rocm_attach_impl_frida_setup.cpp (the ROCm
 * version). Intercepts the MACA runtime entry points exported by
 * libmcruntime.so so kernel launches can be redirected to the
 * instrumented modules produced by maca-pipeline-helper.
 *
 * Hook inventory (12, mirroring the ROCm set):
 *   mcLaunchKernel              (replace)  <<< >>> lowering target
 *   __mcRegisterFunction        (replace)  kernel stub -> mangled name
 *   __mcRegisterVar             (replace)  variable stub -> name
 *   mcMemcpyToSymbol[Async]     (replace)  write-side symbol mirror
 *   mcMemcpyFromSymbol[Async]   (replace)  read-side symbol mirror
 *   mcModuleGetFunction         (replace)  mcFunction_t -> name map
 *   mcModuleLaunchKernel        (replace)  driver-API launch replacement
 *   mcGraphAddKernelNode        (replace)  graph node patching
 *   mcGraphExecKernelNodeSetParams (replace)
 *   mcGraphKernelNodeSetParams  (replace)
 */
#include "maca_attach_impl.hpp"
#include "spdlog/spdlog.h"

#ifdef __has_attribute
#undef __has_attribute
#endif

#include <frida-gum.h>
#include <dlfcn.h>
#include <cctype>
#include <mc_runtime.h>
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

static maca_attach_impl *g_active_maca_impl = nullptr;

// mcLaunchKernel's signature is layout-identical to hipLaunchKernel:
// (const void *function_address, dim3, dim3, void **args, size_t, mcStream_t)
using mcLaunchKernel_fn_t = mcError_t (*)(const void *, dim3, dim3,
					  void **, size_t, mcStream_t);
static mcLaunchKernel_fn_t original_mcLaunchKernel = nullptr;

// mxcc's __mc_module_ctor registers each kernel with the same 10-argument
// ABI shape as CUDA's __cudaRegisterFunction (verified from the emitted
// assembly: 6 register args + a 32-byte stack tail). Only the first four
// arguments matter to the hook; the tail is forwarded untouched, and
// pointer-typed tail parameters occupy the same eight-byte slots, so this
// CUDA-style declaration is ABI-safe for pass-through.
using mcRegisterFunction_fn_t =
	void (*)(void **, const void *, char *, const char *, unsigned int,
		 uint3 *, uint3 *, dim3 *, dim3 *, int *);
static mcRegisterFunction_fn_t original___mcRegisterFunction = nullptr;

// Same shape as CUDA's __cudaRegisterVar (6 register args + 2 stack args,
// matching the emitted assembly).
using mcRegisterVar_fn_t =
	void (*)(void **, void *, const char *, const char *, int,
		 size_t, int, int);
static mcRegisterVar_fn_t original___mcRegisterVar = nullptr;

using mcMemcpyToSymbol_fn_t =
	mcError_t (*)(const void *, const void *, size_t, size_t,
		      mcMemcpyKind);
static mcMemcpyToSymbol_fn_t original_mcMemcpyToSymbol = nullptr;

using mcMemcpyToSymbolAsync_fn_t =
	mcError_t (*)(const void *, const void *, size_t, size_t,
		      mcMemcpyKind, mcStream_t);
static mcMemcpyToSymbolAsync_fn_t original_mcMemcpyToSymbolAsync = nullptr;

using mcMemcpyFromSymbol_fn_t =
	mcError_t (*)(void *, const void *, size_t, size_t,
		      mcMemcpyKind);
static mcMemcpyFromSymbol_fn_t original_mcMemcpyFromSymbol = nullptr;

using mcMemcpyFromSymbolAsync_fn_t =
	mcError_t (*)(void *, const void *, size_t, size_t,
		      mcMemcpyKind, mcStream_t);
static mcMemcpyFromSymbolAsync_fn_t original_mcMemcpyFromSymbolAsync =
	nullptr;

using mcModuleGetFunction_fn_t =
	mcError_t (*)(mcFunction_t *, mcModule_t, const char *);
static mcModuleGetFunction_fn_t original_mcModuleGetFunction = nullptr;

using mcModuleLaunchKernel_fn_t =
	mcError_t (*)(mcFunction_t, unsigned int, unsigned int,
		      unsigned int, unsigned int, unsigned int,
		      unsigned int, unsigned int, mcStream_t, void **,
		      void **);
static mcModuleLaunchKernel_fn_t original_mcModuleLaunchKernel = nullptr;

using mcGraphAddKernelNode_fn_t =
	mcError_t (*)(mcGraphNode_t *, mcGraph_t, const mcGraphNode_t *,
		      size_t, const mcKernelNodeParams *);
static mcGraphAddKernelNode_fn_t original_mcGraphAddKernelNode = nullptr;

using mcGraphExecKernelNodeSetParams_fn_t =
	mcError_t (*)(mcGraphExec_t, mcGraphNode_t,
		      const mcKernelNodeParams *);
static mcGraphExecKernelNodeSetParams_fn_t
	original_mcGraphExecKernelNodeSetParams = nullptr;

using mcGraphKernelNodeSetParams_fn_t =
	mcError_t (*)(mcGraphNode_t, const mcKernelNodeParams *);
static mcGraphKernelNodeSetParams_fn_t original_mcGraphKernelNodeSetParams =
	nullptr;

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

// Strip the mxcc __device_stub__ infix from a mangled symbol:
//   _Z<N>__device_stub__<name><params>  ->  _Z<N-15><name><params>
// ("__device_stub__" is 15 characters). Returns the input unchanged for
// non-stub symbols.
static std::string strip_device_stub_prefix(const std::string &name)
{
	static const std::string stub_infix = "__device_stub__";
	if (name.size() < 4 || name[0] != '_' || name[1] != 'Z')
		return name;
	size_t digits_end = 2;
	while (digits_end < name.size() && isdigit(name[digits_end]))
		digits_end++;
	if (digits_end == 2)
		return name;
	size_t ident_len = (size_t)std::stoul(name.substr(2, digits_end - 2));
	size_t ident_start = digits_end;
	if (ident_start + ident_len > name.size())
		return name;
	std::string ident = name.substr(ident_start, ident_len);
	if (ident.size() <= stub_infix.size() ||
	    ident.compare(0, stub_infix.size(), stub_infix) != 0)
		return name;
	std::string kernel = ident.substr(stub_infix.size());
	return "_Z" + std::to_string(kernel.size()) + kernel +
	       name.substr(ident_start + ident_len);
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
		if (addr == (uintptr_t)func) {
			// mxcc-generated host stubs are mangled as
			// _Z<N>__device_stub__<kernel>...: the application's
			// __mc_module_ctor runs before this library's
			// constructor (the loader runs the executable's
			// init_array ahead of LD_PRELOAD initializers), so
			// the registration hook has not recorded the
			// stub->kernel mapping yet. Recover the kernel name
			// mechanically: strip the __device_stub__ infix and
			// adjust the encoded identifier length
			// (_Z24__device_stub__vectorAddPKfS0_Pf ->
			//  _Z9vectorAddPKfS0_Pf).
			return strip_device_stub_prefix(name);
		}
	}
	return "";
}

static std::string maca_lookup_kernel_name(const void *func)
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

std::string maca_lookup_variable_name(const void *symbol)
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

extern "C" void maca__mcRegisterFunction(
	void **modules, const void *hostFunction, char *deviceFunction,
	const char *deviceName, unsigned int threadLimit, uint3 *tid,
	uint3 *bid, dim3 *blockDim, dim3 *gridDim, int *wSize)
{
	if (hostFunction != nullptr && deviceFunction != nullptr) {
		std::lock_guard<std::mutex> lock(g_kernel_stub_mutex);
		g_kernel_stub_names[hostFunction] = deviceFunction;
		SPDLOG_DEBUG(
			"Registered MACA kernel stub {} -> '{}'",
			(void *)hostFunction, deviceFunction);
	}
	if (original___mcRegisterFunction) {
		original___mcRegisterFunction(modules, hostFunction,
					      deviceFunction, deviceName,
					      threadLimit, tid, bid, blockDim,
					      gridDim, wSize);
	}
}

extern "C" mcError_t
maca__mcLaunchKernel(const void *func, dim3 gridDim, dim3 blockDim,
		     void **args, size_t sharedMem, mcStream_t stream)
{
	auto forward = [&]() -> mcError_t {
		return original_mcLaunchKernel
			       ? original_mcLaunchKernel(func, gridDim,
							 blockDim, args,
							 sharedMem, stream)
			       : mcLaunchKernel(func, gridDim, blockDim, args,
						sharedMem, stream);
	};

	SPDLOG_DEBUG("maca hook: mcLaunchKernel func={} enabled={}",
		     (const void *)func,
		     g_active_maca_impl ?
			     (int)g_active_maca_impl->is_enabled() :
			     -1);
	if (!g_active_maca_impl || !g_active_maca_impl->is_enabled())
		return forward();

	std::string kernel_name = maca_lookup_kernel_name(func);
	if (kernel_name.empty()) {
		SPDLOG_DEBUG(
			"No registered MACA kernel name for func {}, bypassing",
			(void *)func);
		return forward();
	}

	auto kernel_func =
		g_active_maca_impl->find_instrumented_kernel_function(
			kernel_name);
	if (!kernel_func) {
		return forward();
	}

	SPDLOG_DEBUG(
		"Redirecting mcLaunchKernel({}) -> instrumented kernel",
		kernel_name);

	// Call the ORIGINAL mcModuleLaunchKernel directly (not through the
	// Frida-replaced symbol): calling the symbol would re-enter our own
	// maca__mcModuleLaunchKernel hook, whose Frida trampoline round-trip
	// has been observed to corrupt the 11-argument ABI (stack arguments)
	// and fail with mcErrorMemoryValueTooLarge.
	mcError_t err = original_mcModuleLaunchKernel
		? original_mcModuleLaunchKernel(
			*kernel_func, gridDim.x, gridDim.y, gridDim.z,
			blockDim.x, blockDim.y, blockDim.z, sharedMem, stream,
			args, nullptr)
		: mcModuleLaunchKernel(
			*kernel_func, gridDim.x, gridDim.y, gridDim.z,
			blockDim.x, blockDim.y, blockDim.z, sharedMem, stream,
			args, nullptr);
	if (err != mcSuccess) {
		SPDLOG_ERROR(
			"Failed to launch instrumented kernel {}: {} (code={} func={:x} grid={}x{}x{} block={}x{}x{} shmem={} args={:x})",
			kernel_name, mcGetErrorString(err), (int)err,
			(uintptr_t)*kernel_func, gridDim.x, gridDim.y,
			gridDim.z, blockDim.x, blockDim.y, blockDim.z,
			sharedMem, (uintptr_t)args);
		return forward();
	}
	g_active_maca_impl->record_patched_launch(stream);
	return mcSuccess;
}

extern "C" void maca__mcRegisterVar(
	void **fatbinHandle, void *hostVar, const char *deviceName,
	const char *hostName, int ext, size_t size, int constant,
	int global)
{
	if (hostVar != nullptr && deviceName != nullptr) {
		std::lock_guard<std::mutex> lock(g_variable_stub_mutex);
		g_variable_stub_names[hostVar] = deviceName;
		SPDLOG_DEBUG(
			"Registered MACA variable {} -> '{}'",
			hostVar, deviceName);
	}
	if (original___mcRegisterVar) {
		original___mcRegisterVar(fatbinHandle, hostVar, deviceName,
					 hostName, ext, size, constant,
					 global);
	}
}

extern "C" mcError_t maca__mcMemcpyToSymbol(
	const void *symbol, const void *src, size_t count, size_t offset,
	mcMemcpyKind kind)
{
	auto original = [&]() -> mcError_t {
		return original_mcMemcpyToSymbol
			       ? original_mcMemcpyToSymbol(symbol, src, count,
							   offset, kind)
			       : mcMemcpyToSymbol(symbol, src, count, offset,
						  kind);
	};
	auto err = original();
	if (g_active_maca_impl && g_active_maca_impl->is_enabled()) {
		g_active_maca_impl->mirror_maca_memcpy_to_symbol(
			symbol, src, count, offset, (int)kind);
	}
	return err;
}

extern "C" mcError_t maca__mcMemcpyToSymbolAsync(
	const void *symbol, const void *src, size_t count, size_t offset,
	mcMemcpyKind kind, mcStream_t stream)
{
	auto original = [&]() -> mcError_t {
		return original_mcMemcpyToSymbolAsync
			       ? original_mcMemcpyToSymbolAsync(symbol, src,
								count, offset,
								kind, stream)
			       : mcMemcpyToSymbolAsync(symbol, src, count,
						       offset, kind, stream);
	};
	auto err = original();
	if (g_active_maca_impl && g_active_maca_impl->is_enabled()) {
		g_active_maca_impl->mirror_maca_memcpy_to_symbol(
			symbol, src, count, offset, (int)kind);
	}
	return err;
}

extern "C" mcError_t maca__mcMemcpyFromSymbol(
	void *dst, const void *symbol, size_t count, size_t offset,
	mcMemcpyKind kind)
{
	auto original = [&]() -> mcError_t {
		return original_mcMemcpyFromSymbol
			       ? original_mcMemcpyFromSymbol(dst, symbol,
							     count, offset,
							     kind)
			       : mcMemcpyFromSymbol(dst, symbol, count,
						     offset, kind);
	};
	if (!g_active_maca_impl || !g_active_maca_impl->is_enabled())
		return original();
	if (g_active_maca_impl->mirror_maca_memcpy_from_symbol(
		    dst, symbol, count, offset, (int)kind))
		return mcSuccess;
	return original();
}

extern "C" mcError_t maca__mcMemcpyFromSymbolAsync(
	void *dst, const void *symbol, size_t count, size_t offset,
	mcMemcpyKind kind, mcStream_t stream)
{
	auto original = [&]() -> mcError_t {
		return original_mcMemcpyFromSymbolAsync
			       ? original_mcMemcpyFromSymbolAsync(
				     dst, symbol, count, offset, kind, stream)
			       : mcMemcpyFromSymbolAsync(dst, symbol, count,
							 offset, kind,
							 stream);
	};
	if (!g_active_maca_impl || !g_active_maca_impl->is_enabled())
		return original();
	if (g_active_maca_impl->mirror_maca_memcpy_from_symbol(
		    dst, symbol, count, offset, (int)kind))
		return mcSuccess;
	return original();
}

extern "C" mcError_t maca__mcModuleGetFunction(
	mcFunction_t *function, mcModule_t module, const char *kname)
{
	auto err = original_mcModuleGetFunction
			   ? original_mcModuleGetFunction(function, module,
							  kname)
			   : mcModuleGetFunction(function, module, kname);
	if (err == mcSuccess && g_active_maca_impl &&
	    g_active_maca_impl->is_enabled() && function && *function &&
	    kname && kname[0]) {
		g_active_maca_impl->record_kernel_function_name(*function,
								 kname);
	}
	return err;
}

extern "C" mcError_t maca__mcModuleLaunchKernel(
	mcFunction_t f, unsigned int gridDimX, unsigned int gridDimY,
	unsigned int gridDimZ, unsigned int blockDimX,
	unsigned int blockDimY, unsigned int blockDimZ,
	unsigned int sharedMemBytes, mcStream_t stream,
	void **kernelParams, void **extra)
{
	SPDLOG_DEBUG(
		"maca hook: mcModuleLaunchKernel f={:x} grid={}x{}x{} block={}x{}x{} shmem={} stream={:x} params={:x}",
		(uintptr_t)f, gridDimX, gridDimY, gridDimZ, blockDimX,
		blockDimY, blockDimZ, sharedMemBytes, (uintptr_t)stream,
		(uintptr_t)kernelParams);
	auto original = [&]() -> mcError_t {
		return original_mcModuleLaunchKernel
			       ? original_mcModuleLaunchKernel(
				 f, gridDimX, gridDimY, gridDimZ, blockDimX,
				 blockDimY, blockDimZ, sharedMemBytes,
				 stream, kernelParams, extra)
			       : mcModuleLaunchKernel(
				 f, gridDimX, gridDimY, gridDimZ, blockDimX,
				 blockDimY, blockDimZ, sharedMemBytes,
				 stream, kernelParams, extra);
	};
	if (!g_active_maca_impl || !g_active_maca_impl->is_enabled())
		return original();
	auto name =
		g_active_maca_impl->find_kernel_name_by_function(f);
	if (name) {
		auto instrumented =
			g_active_maca_impl
				->find_instrumented_kernel_function(*name);
		if (instrumented && *instrumented != f) {
			f = *instrumented;
			g_active_maca_impl->record_patched_launch(stream);
		}
	}
	return original();
}

static const mcKernelNodeParams *
maca_graph_maybe_patch_kernel_node_params(
	maca_attach_impl &impl, const mcKernelNodeParams *params,
	mcKernelNodeParams &patched)
{
	if (!params || !params->func)
		return params;
	auto name = impl.find_kernel_name_by_function(
		(mcFunction_t)params->func);
	if (!name)
		return params;
	auto instrumented =
		impl.find_instrumented_kernel_function(*name);
	if (!instrumented)
		return params;
	patched = *params;
	patched.func = (void *)*instrumented;
	return &patched;
}

extern "C" mcError_t maca__mcGraphAddKernelNode(
	mcGraphNode_t *pGraphNode, mcGraph_t graph,
	const mcGraphNode_t *pDependencies, size_t numDependencies,
	const mcKernelNodeParams *pNodeParams)
{
	auto original = [&](mcGraphNode_t *pGraphNode, mcGraph_t graph,
			    const mcGraphNode_t *pDependencies,
			    size_t numDependencies,
			    const mcKernelNodeParams *pNodeParams) -> mcError_t {
		return original_mcGraphAddKernelNode
			       ? original_mcGraphAddKernelNode(
				 pGraphNode, graph, pDependencies,
				 numDependencies, pNodeParams)
			       : mcGraphAddKernelNode(
				 pGraphNode, graph, pDependencies,
				 numDependencies, pNodeParams);
	};
	if (!g_active_maca_impl || !g_active_maca_impl->is_enabled())
		return original(pGraphNode, graph, pDependencies,
				numDependencies, pNodeParams);
	mcKernelNodeParams patched;
	auto params = maca_graph_maybe_patch_kernel_node_params(
		*g_active_maca_impl, pNodeParams, patched);
	return original(pGraphNode, graph, pDependencies, numDependencies,
			params);
}

extern "C" mcError_t maca__mcGraphExecKernelNodeSetParams(
	mcGraphExec_t hGraphExec, mcGraphNode_t node,
	const mcKernelNodeParams *pNodeParams)
{
	auto original = [&](mcGraphExec_t hGraphExec, mcGraphNode_t node,
			    const mcKernelNodeParams *pNodeParams)
				    -> mcError_t {
		return original_mcGraphExecKernelNodeSetParams
			       ? original_mcGraphExecKernelNodeSetParams(
				 hGraphExec, node, pNodeParams)
			       : mcGraphExecKernelNodeSetParams(hGraphExec,
								 node,
								 pNodeParams);
	};
	if (!g_active_maca_impl || !g_active_maca_impl->is_enabled())
		return original(hGraphExec, node, pNodeParams);
	mcKernelNodeParams patched;
	auto params = maca_graph_maybe_patch_kernel_node_params(
		*g_active_maca_impl, pNodeParams, patched);
	return original(hGraphExec, node, params);
}

extern "C" mcError_t maca__mcGraphKernelNodeSetParams(
	mcGraphNode_t node, const mcKernelNodeParams *pNodeParams)
{
	auto original = [&](mcGraphNode_t node,
			    const mcKernelNodeParams *pNodeParams)
				    -> mcError_t {
		return original_mcGraphKernelNodeSetParams
			       ? original_mcGraphKernelNodeSetParams(node,
								    pNodeParams)
			       : mcGraphKernelNodeSetParams(node,
							    pNodeParams);
	};
	if (!g_active_maca_impl || !g_active_maca_impl->is_enabled())
		return original(node, pNodeParams);
	mcKernelNodeParams patched;
	auto params = maca_graph_maybe_patch_kernel_node_params(
		*g_active_maca_impl, pNodeParams, patched);
	return original(node, params);
}

void maca_clear_global_state()
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

namespace {

// Boilerplate for one replace-hook installation.
struct hook_desc {
	const char *symbol;
	gpointer replacement;
	gpointer *original_slot;
	const char *name_for_log;
};

void install_replacement(GumInterceptor *interceptor,
			 const hook_desc &desc)
{
	void *addr = GSIZE_TO_POINTER(
		gum_module_find_export_by_name(nullptr, desc.symbol));
	if (!addr) {
		SPDLOG_WARN("maca_attach_impl: {} symbol not found",
			    desc.symbol);
		return;
	}
	gpointer original_tmp = nullptr;
	auto err = gum_interceptor_replace(interceptor, addr,
					   desc.replacement, nullptr,
					   &original_tmp);
	if (err == GUM_REPLACE_OK) {
		*desc.original_slot = original_tmp;
		SPDLOG_INFO("maca_attach_impl: replaced {}",
			    desc.name_for_log);
	} else {
		SPDLOG_ERROR(
			"maca_attach_impl: failed to replace {}: {}",
			desc.name_for_log, (int)err);
	}
}

} // namespace

void maca_attach_impl_setup_frida_hooks(maca_attach_impl *impl)
{
	gum_init_embedded();
	auto interceptor = gum_interceptor_obtain();
	if (!interceptor) {
		SPDLOG_ERROR(
			"maca_attach_impl: failed to obtain Frida interceptor");
		return;
	}
	impl->frida_interceptor = interceptor;

	gum_interceptor_begin_transaction(interceptor);

	const hook_desc hooks[] = {
		{ "mcLaunchKernel",
		  (gpointer)&maca__mcLaunchKernel,
		  (gpointer *)&original_mcLaunchKernel,
		  "mcLaunchKernel" },
		{ "__mcRegisterFunction",
		  (gpointer)&maca__mcRegisterFunction,
		  (gpointer *)&original___mcRegisterFunction,
		  "__mcRegisterFunction" },
		{ "__mcRegisterVar",
		  (gpointer)&maca__mcRegisterVar,
		  (gpointer *)&original___mcRegisterVar,
		  "__mcRegisterVar" },
		{ "mcMemcpyToSymbol",
		  (gpointer)&maca__mcMemcpyToSymbol,
		  (gpointer *)&original_mcMemcpyToSymbol,
		  "mcMemcpyToSymbol" },
		{ "mcMemcpyToSymbolAsync",
		  (gpointer)&maca__mcMemcpyToSymbolAsync,
		  (gpointer *)&original_mcMemcpyToSymbolAsync,
		  "mcMemcpyToSymbolAsync" },
		{ "mcMemcpyFromSymbol",
		  (gpointer)&maca__mcMemcpyFromSymbol,
		  (gpointer *)&original_mcMemcpyFromSymbol,
		  "mcMemcpyFromSymbol" },
		{ "mcMemcpyFromSymbolAsync",
		  (gpointer)&maca__mcMemcpyFromSymbolAsync,
		  (gpointer *)&original_mcMemcpyFromSymbolAsync,
		  "mcMemcpyFromSymbolAsync" },
		{ "mcModuleGetFunction",
		  (gpointer)&maca__mcModuleGetFunction,
		  (gpointer *)&original_mcModuleGetFunction,
		  "mcModuleGetFunction" },
		{ "mcModuleLaunchKernel",
		  (gpointer)&maca__mcModuleLaunchKernel,
		  (gpointer *)&original_mcModuleLaunchKernel,
		  "mcModuleLaunchKernel" },
		{ "mcGraphAddKernelNode",
		  (gpointer)&maca__mcGraphAddKernelNode,
		  (gpointer *)&original_mcGraphAddKernelNode,
		  "mcGraphAddKernelNode" },
		{ "mcGraphExecKernelNodeSetParams",
		  (gpointer)&maca__mcGraphExecKernelNodeSetParams,
		  (gpointer *)&original_mcGraphExecKernelNodeSetParams,
		  "mcGraphExecKernelNodeSetParams" },
		{ "mcGraphKernelNodeSetParams",
		  (gpointer)&maca__mcGraphKernelNodeSetParams,
		  (gpointer *)&original_mcGraphKernelNodeSetParams,
		  "mcGraphKernelNodeSetParams" },
	};
	for (const auto &h : hooks)
		install_replacement(interceptor, h);

	gum_interceptor_end_transaction(interceptor);

	g_active_maca_impl = impl;
}

} // namespace attach
} // namespace gprobe
