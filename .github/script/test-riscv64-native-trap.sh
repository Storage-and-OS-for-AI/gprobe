#!/usr/bin/env bash
set -euo pipefail

case "$(uname -m)" in
    riscv64) ;;
    *)
        echo "riscv64 host required; refusing qemu-user or cross-architecture evidence" >&2
        exit 2
        ;;
esac

if [[ -n "$(git status --porcelain --untracked-files=no --ignore-submodules=none)" ]]; then
    echo "clean tracked worktree and submodules required for reproducible evidence" >&2
    exit 3
fi

build_dir="${1:-build-native-riscv64-trap}"
build_type="${BUILD_TYPE:-Release}"

echo "commit=$(git rev-parse HEAD)"
echo "kernel=$(uname -srvm)"
if command -v lscpu >/dev/null 2>&1; then
    lscpu
elif [[ -r /proc/cpuinfo ]]; then
    cat /proc/cpuinfo
else
    echo "CPU topology unavailable"
fi
echo "hardware provenance must be supplied separately by the operator"

cmake -S . -B "$build_dir" -G "Unix Makefiles" \
    -DCMAKE_BUILD_TYPE="$build_type" \
    -DBUILD_GPROBE_DAEMON=OFF \
    -DGPROBE_ENABLE_UNIT_TESTING=ON \
    -DGPROBE_ENABLE_FRIDA=OFF \
    -DGPROBE_ENABLE_TRAP_UPROBE=ON \
    -DENABLE_EBPF_VERIFIER=OFF \
    -DGPROBE_LLVM_JIT=OFF \
    -DGPROBE_BUILD_WITH_LIBBPF=OFF

cmake --build "$build_dir" \
    --target gprobe_trap_uprobe_attach_tests gprobe_trap_late_host \
    -j"$(nproc)"

trap_tests="$build_dir/attach/trap_uprobe_attach_impl/gprobe_trap_uprobe_attach_tests"
late_host="$build_dir/attach/trap_uprobe_attach_impl/gprobe_trap_late_host"
late_module="$build_dir/attach/trap_uprobe_attach_impl/libgprobe_trap_late_module.so"

"$trap_tests" "Trap backend: concurrent three-phase patch*"
"$trap_tests" "Trap backend: handler signal-safety*,Trap backend: new threads*"
"$late_host" "$late_module"
