/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026
 * All rights reserved.
 *
 * MACA eBPF simple counter server loader: port of
 * example/gpu/rocm_simple_counter/rocm_simple_counter.c (the ROCm version).
 *
 * Run under the gprobe syscall-server:
 *   LD_PRELOAD=build/runtime/syscall-server/libgprobe-syscall-server.so \
 *       ./maca_simple_counter
 */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "maca_simple_counter.skel.h"
#include <inttypes.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct maca_simple_counter_bpf *skel;
	int err;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = maca_simple_counter_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = maca_simple_counter_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = maca_simple_counter_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	while (!exiting) {
		sleep(1);
		uint32_t key = 0;
		uint64_t value = 0;
		int mapfd = bpf_map__fd(skel->maps.counter);
		if (bpf_map_lookup_elem(mapfd, &key, &value) == 0) {
			printf("counter[0]=%lu\n", (unsigned long)value);
		}
	}
cleanup:
	/* Clean up */
	maca_simple_counter_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
