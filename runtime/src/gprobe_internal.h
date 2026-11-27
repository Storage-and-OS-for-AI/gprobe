/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#ifndef EBPF_RUNTIME_INTERNEL_H_
#define EBPF_RUNTIME_INTERNEL_H_

#include <cstdint>
#include <cstddef>
#include "gprobe.hpp"
#include <gprobe_ufunc.hpp>
namespace gprobe
{

class gprobe_prog;
class gprobe_object;

typedef gprobe_prog *gprobe_prog_ptr;

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

struct gprobe_ufunc_ctx {
	struct ebpf_ufunc_func_info ufunc_funcs[MAX_UFUNC_FUNCS];
	size_t ufunc_func_cnt;
};

// not used directly
#define UFUNC_HELPER_ID_DISPATCHER 1000
#define UFUNC_HELPER_ID_FIND_ID 1001

// find the ufunc id from the function name
// not used directly
extern "C" uint64_t __ebpf_call_ufunc_dispatcher(uint64_t id,
						 uint64_t arg_list);

// find the ufunc id from the function name
// not used directly
extern "C" int64_t __ebpf_call_find_ufunc_id(const char *func_name);

extern "C" uint64_t map_ptr_by_fd(uint32_t fd);

extern "C" uint64_t map_val(uint64_t map_ptr);

} // namespace gprobe

#endif // EBPF_RUNTIME_INTERNEL_H_
