#ifndef _GPROBE_RUNTIME_HEADERS_H_
#define _GPROBE_RUNTIME_HEADERS_H_

#include <ebpf-vm.h>
#include "gprobe_config.hpp"
#include "bpf_attach_ctx.hpp"
#include "gprobe_ufunc.hpp"
#include "gprobe_helper_group.hpp"
#include "gprobe_prog.hpp"
#include "gprobe_shm.hpp"

extern "C" {

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};
struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
	char __data[0];
};
struct _FridaUprobeListener;
typedef struct _GumInterceptor GumInterceptor;
typedef struct _GumInvocationListener GumInvocationListener;
}

#endif
