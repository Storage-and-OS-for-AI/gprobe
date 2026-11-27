/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#ifndef _GPROBE_PROG_HPP
#define _GPROBE_PROG_HPP

#include "gprobe_config.hpp"
#include <ebpf-vm.h>
#include <optional>
#include <vector>
#include <string>
#include <map>
namespace gprobe
{

extern thread_local std::optional<uint64_t> current_thread_bpf_cookie;
extern thread_local std::optional<uint64_t> current_thread_tail_call_ret;
#ifdef GPROBE_ENABLE_CUDA_ATTACH
std::optional<std::vector<char>> compile_ptx_to_elf(const std::string &ptx_code,
						    const char *cpu_target);
#endif
// executable program for bpf function
class gprobe_prog {
    public:
	const char *prog_name() const
	{
		return name.c_str();
	}
	gprobe_prog(const ebpf_inst *insn, size_t insn_cnt, const char *name);
	gprobe_prog(const ebpf_inst *insn, size_t insn_cnt, const char *name,
		     runtime_config config);
	~gprobe_prog();

	// load the programs to userspace vm or compile the jit program
	// if program_name is NULL, will load the first program in the object
	int gprobe_prog_load(bool jit);
	int gprobe_prog_unload();
	// Validate all external calls and compile before installing a signal probe.
	// Returns -ENOTSUP for unaudited helpers or an unavailable eager JIT.
	int prepare_for_signal_execution();

	// exec in user space
	int gprobe_prog_exec(void *memory, size_t memory_size,
			      uint64_t *return_val) const;

	int gprobe_prog_register_raw_helper(struct gprobe_helper_info info);
	const std::vector<ebpf_inst> &get_insns() const
	{
		return insns;
	}
	const struct ebpf_vm *get_vm() const
	{
		return vm;
	}
	int load_aot_object(const std::vector<uint8_t> &buf);
#ifdef GPROBE_ENABLE_CUDA_ATTACH
	bool is_cuda() const
	{
		return name.starts_with("cuda__");
	}
	const void *get_cuda_elf_binary() const
	{
		return cuda_elf_binary->data();
	}

	const std::string &get_ptx_code() const
	{
		return *ptx_code;
	}
#else
	bool is_cuda() const
	{
		return false;
	}

#endif
#ifdef GPROBE_ENABLE_ROCM_ATTACH
	bool is_rocm() const
	{
		return name.starts_with("rocm__");
	}
#else
	bool is_rocm() const
	{
		return false;
	}
#endif
#ifdef GPROBE_ENABLE_MACA_ATTACH
	bool is_maca() const
	{
		return name.starts_with("maca__");
	}
#else
	bool is_maca() const
	{
		return false;
	}
#endif
    private:
	int gprobe_prog_set_insn(struct ebpf_inst *insn, size_t insn_cnt);
	std::string name;
	// vm at the first element
	struct ebpf_vm *vm;

	bool jitted = false;
	bool program_loaded = false;
	bool signal_ready = false;
	bool loaded_from_aot = false;
	std::map<unsigned, bool> signal_safe_helpers;

	// used in jit
	ebpf_jit_fn fn = nullptr;
	std::vector<struct ebpf_inst> insns;

	char *errmsg = nullptr;

	// ufunc ctx
	struct gprobe_ufunc_ctx *ufunc_ctx;

#ifdef GPROBE_ENABLE_CUDA_ATTACH
	// ptx code
	std::optional<std::string> ptx_code;
	// cuda binary
	std::optional<std::vector<char>> cuda_elf_binary;
#endif
};

} // namespace gprobe
#endif
