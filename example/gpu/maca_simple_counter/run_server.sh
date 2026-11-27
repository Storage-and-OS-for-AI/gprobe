#!/bin/bash
# E2E runner for maca_simple_counter (terminal 1 side: the syscall-server +
# the loader that prints counter[0] once a second). Counterpart of
# run_agent.sh, which drives terminal 2.
#
# LD_LIBRARY_PATH is mandatory here, not cosmetic: gprobe is built with
# /opt/gcc-12/bin/g++, so libgprobe-syscall-server.so and libLLVM-15.so need
# GLIBCXX_3.4.30. The system /usr/lib64/libstdc++.so.6 is GCC 11 (tops out at
# GLIBCXX_3.4.29) and /opt/gcc-12/lib64 is in neither ld.so.cache nor
# /etc/ld.so.conf.d, so without this the preloaded library fails its symbol
# version check at exec time.
#
# LD_PRELOAD is attached to the loader only, via `env` at the end of the chain.
# Do NOT export it for the whole script: the syscall-server constructor ends
# with an unconditional unsetenv("LD_PRELOAD") (runtime/syscall-server/
# syscall_context.hpp, "to avoid polluting other child processes"). So if a
# wrapper such as `stdbuf` or `timeout` is preloaded first, it wipes the
# variable and every process it execs afterwards — including the loader — gets
# no gprobe at all. The loader then talks to the real kernel, which rejects
# map type 1503 with -EINVAL, and the log shows a complete gprobe init (from
# the wrapper) but no `SYS_BPF` / `Creating map type=` lines.
# Keeping `timeout` outermost and setting LD_PRELOAD only for the final program
# avoids that entirely.
#
# No stdbuf here: maca_simple_counter.c already calls setvbuf(_IONBF) on both
# stdout and stderr, so its output is unbuffered even when redirected. Note
# that `env LD_PRELOAD=X` would overwrite the libstdbuf.so that stdbuf appends
# anyway, so stdbuf cannot be combined with this pattern.
#
# Hygiene: remove a stale /dev/shm/gprobe_maps_shm before starting so the run
# begins with no leftover map/prog/link handlers from a previous session. Only
# do this when no other gprobe process is live. (A pre-existing segment is not
# by itself fatal — the loader opens it with shm_open_type 3 and still works —
# but a clean segment makes the counter values comparable between runs.)
#
# Usage: run_server.sh <seconds-to-run>
set -u
DUR=${1:-30}
cd "$(dirname "$0")/../../.." || exit 1
REPO=$PWD

SERVER_SO="$REPO/build/runtime/syscall-server/libgprobe-syscall-server.so"

export LD_LIBRARY_PATH=/opt/maca/lib:/opt/gcc-12/lib64:/opt/llvm-15/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export GPROBE_LOG_OUTPUT=console

exec timeout --signal=INT "$DUR" \
	env LD_PRELOAD="$SERVER_SO" \
	./example/gpu/maca_simple_counter/maca_simple_counter
