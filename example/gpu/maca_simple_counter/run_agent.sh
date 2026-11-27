#!/bin/bash
# E2E runner for maca_simple_counter (terminal 2 side: the agent + vec_add).
# Counterpart of run_server.sh, which drives terminal 1.
#
# LD_LIBRARY_PATH is mandatory here, not cosmetic: gprobe is built with
# /opt/gcc-12/bin/g++, so libgprobe-agent.so and libLLVM-15.so need
# GLIBCXX_3.4.30. vec_add is a C++ binary that needs libstdc++.so.6 itself and
# whose DT_RPATH (/opt/maca/lib:/opt/maca/mxgpu_llvm/lib) does not contain it,
# so without this the loader resolves the system /usr/lib64/libstdc++.so.6
# (GCC 11, max GLIBCXX_3.4.29) first and the preloaded agent then fails its
# symbol version check at exec time:
#   version `GLIBCXX_3.4.30' not found (required by libgprobe-agent.so)
#
# LD_PRELOAD is attached to vec_add only, via `env` inside the chain. Do not
# export it for the whole script: every wrapper (`timeout`, and `stdbuf` if
# present) would then run the agent constructor too — each one registers the
# 50 MB shm segment with MACA, spawns a watcher thread and installs the Frida
# hooks, producing duplicated init blocks, spurious
# mcErrorHostMemoryAlreadyRegistered errors and a segment that outlives them.
# Measured with the old export-based form: 3 constructor runs across 3 pids.
#
# Note the asymmetry with run_server.sh: libgprobe-agent.so does NOT wipe
# LD_PRELOAD, so it propagates into every child (hence the 3 inits), whereas
# libgprobe-syscall-server.so unsetenv()s it in its constructor, which breaks
# the wrapper chain in the opposite way — the loader ends up with no gprobe at
# all. Both scripts therefore keep LD_PRELOAD off the wrappers.
#
# No stdbuf: spdlog's console sink flushes after every record, so the agent's
# own logs stay live when redirected; vec_add's std::cout is line-buffered on
# a terminal. Redirecting to a file makes those cout lines block-buffered and
# a SIGINT kill loses the unflushed tail — read the agent log for the attach
# outcome and the server log for the counter.
#
# Leave GPROBE_MACA_HELPER_PATH unset so the compiled-in
# attach/maca_attach_impl/trampoline/default_trampoline.maca is used. Pointing
# it at a minimal trampoline drops the _bpf_helper_ext_<id> definitions the
# eBPF program calls and the attach is rejected before mcModuleLoadData.
#
# Usage: run_agent.sh <seconds-to-run>
set -u
DUR=${1:-25}
cd "$(dirname "$0")/../../.." || exit 1
REPO=$PWD

AGENT_SO="$REPO/build/runtime/agent/libgprobe-agent.so"

export LD_LIBRARY_PATH=/opt/maca/lib:/opt/gcc-12/lib64:/opt/llvm-15/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export SPDLOG_LEVEL=info
export GPROBE_LOG_OUTPUT=console
export GPROBE_MACA_SOURCE="$REPO/example/gpu/maca_simple_counter/vec_add.maca"

exec timeout --signal=INT "$DUR" \
	env LD_PRELOAD="$AGENT_SO" \
	./example/gpu/maca_simple_counter/vec_add
