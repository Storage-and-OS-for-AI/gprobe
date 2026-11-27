#!/usr/bin/env bash
set -euo pipefail
ROOT="/root/gprobe_sy03/gprobe"
CLI="$ROOT/build/tools/cli/gprobe"
RUNON="$ROOT/build/tools/gprobetool/gprobetool"
PROG="$ROOT/example/gpu/directly_run_on_gpu/directly_run"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

ulimit -l unlimited || true
GPROBE_LOG_OUTPUT=console GPROBE_SHM_MEMORY_MB=${GPROBE_SHM_MEMORY_MB:-16} prlimit --memlock=unlimited -- "$CLI" load "$PROG" &
SERVER_PID=$!
sleep 2

# N=1024 -> grid=4x1x1, block=256x1x1
prlimit --memlock=unlimited -- "$RUNON" run-on-cuda cuda__vec_add 1 4 1 1 256 1 1
sleep 1
#!/usr/bin/env bash
set -euo pipefail
ROOT="/root/gprobe_sy03/gprobe"
CLI="$ROOT/build/tools/cli/gprobe"
RUNON="$ROOT/build/tools/gprobetool/gprobetool"
PROG="$ROOT/example/gpu/directly_run_on_gpu/directly_run"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

GPROBE_LOG_OUTPUT=console "$CLI" load "$PROG" &
SERVER_PID=$!
sleep 2

# Minimal: grid=4x1x1, block=256x1x1 to cover N=1024
"$RUNON" run-on-cuda cuda__vec_add 1 4 1 1 256 1 1
sleep 1



