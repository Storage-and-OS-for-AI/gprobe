/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026
 * All rights reserved.
 *
 * MACA eBPF simple counter: port of example/gpu/rocm_simple_counter/
 * rocm_simple_counter.bpf.c. The eBPF program name carries the `maca__`
 * prefix so a future maca_attach_impl can route it, mirroring the
 * `rocm__`/`cuda__` conventions.
 */
#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BPF_MAP_TYPE_GPU_ARRAY_MAP 1503


struct {
	__uint(type, BPF_MAP_TYPE_GPU_ARRAY_MAP);
	__uint(max_entries, 4);
	__type(key, u32);
	__type(value, u64);
} counter SEC(".maps");

SEC("kprobe/_Z9vectorAddPKfS0_Pf")
int maca__trace_maca_kernel(struct pt_regs *ctx)
{
	u32 key = 0;
	u64 *val = bpf_map_lookup_elem(&counter, &key);
	if (val)
		*val = *val + 1;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
