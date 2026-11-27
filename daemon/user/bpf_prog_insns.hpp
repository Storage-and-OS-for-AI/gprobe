/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#ifndef GPROBE_BPF_PROG_INSNS_HPP
#define GPROBE_BPF_PROG_INSNS_HPP

#include "ebpf_inst.h"
#include <cerrno>
#include <cstring>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <vector>
#include "../bpf_tracer_event.h"

namespace gprobe::detail
{

inline int copy_captured_bpf_prog_insns(std::vector<ebpf_inst> &insns,
					const bpf_insn_data &captured)
{
	static_assert(sizeof(bpf_insn) == sizeof(ebpf_inst));
	constexpr size_t captured_capacity =
		sizeof(captured.code) / sizeof(ebpf_inst);
	if (captured.code_len > captured_capacity) {
		insns.clear();
		return -E2BIG;
	}

	insns.resize(captured.code_len);
	if (!insns.empty()) {
		std::memcpy(insns.data(), captured.code,
			    captured.code_len * sizeof(ebpf_inst));
	}
	return 0;
}

} // namespace gprobe::detail

#endif // GPROBE_BPF_PROG_INSNS_HPP
