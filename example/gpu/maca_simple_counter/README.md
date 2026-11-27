# MACA eBPF Simple Counter Example (Single kprobe)

Port of `example/gpu/rocm_simple_counter/` (ROCm/HIP) to the MetaX MACA
platform. The minimal MACA GPU eBPF example: a single eBPF program with one
kprobe attached to a MACA kernel (`_Z9vectorAddPKfS0_Pf`), incrementing a
counter map entry on every launch.

The eBPF program name carries the `maca__` prefix
(`maca__trace_maca_kernel`) so `maca_attach_impl` routes it to the MACA
attach backend (mirroring the `rocm__`/`cuda__` conventions).

## Files

- `vec_add.maca` — baseline GPU program, built with `mxcc`, runs on the
  MetaX C500. Launches `vectorAdd` in a 1 Hz infinite loop.
- `maca_simple_counter.bpf.c` — the eBPF object: one kprobe on
  `_Z9vectorAddPKfS0_Pf` that increments `counter[0]` of a
  `BPF_MAP_TYPE_GPU_ARRAY_MAP` (1503) via `bpf_map_lookup_elem`.
- `maca_simple_counter.c` — server-side loader (skeleton open/load/attach,
  then prints `counter[0]` once a second).
- `run_server.sh` / `run_agent.sh` — the two terminals of the end-to-end run.

## Build

Requirements: MACA SDK at `/opt/maca` (mxcc), clang with BPF target.

```sh
make -C example/gpu/maca_simple_counter
```

gprobe itself must be configured with `-DGPROBE_ENABLE_MACA_ATTACH=ON
-DBUILD_LLVM_MACA_CLI=ON -DGPROBE_MACA_ROOT=/opt/maca`.

## Run the baseline

```sh
./example/gpu/maca_simple_counter/vec_add
# C[0] = 0 (expected 0)
# C[1] = 3 (expected 3)
# ... (one pair per second, Ctrl-C to stop)
```

## Run end-to-end (two terminals)

Both scripts export `LD_LIBRARY_PATH=/opt/maca/lib:/opt/gcc-12/lib64:/opt/llvm-15/lib`.
That is mandatory: gprobe is built with `/opt/gcc-12/bin/g++`, so the
preloaded libraries need `GLIBCXX_3.4.30`, which a GCC 11
`/usr/lib64/libstdc++.so.6` does not provide and which is not in
`ld.so.cache`. Running the binaries by hand without it fails at exec time
with `version 'GLIBCXX_3.4.30' not found`.

```sh
# terminal 1 — syscall-server + loader
rm -f /dev/shm/gprobe_maps_shm   # only when no other gprobe process is live
bash example/gpu/maca_simple_counter/run_server.sh 30

# terminal 2 — agent injected into vec_add
bash example/gpu/maca_simple_counter/run_agent.sh 25
```

Expected: terminal 2 reports `instrumented kernel _Z9vectorAddPKfS0_Pf
ready` and keeps printing `C[1] = 3`; terminal 1's `counter[0]` increments
by one per second instead of staying at 0.

Add `GPROBE_MACA_KEEP_IR=1` to terminal 2 to keep the pipeline's
intermediate IR and device object under `/tmp/gprobe_maca_*` for inspection.
Leave `GPROBE_MACA_HELPER_PATH` **unset**: overriding it with a minimal
trampoline drops the `_bpf_helper_ext_<id>` definitions the eBPF program
calls, and the attach is then rejected before `mcModuleLoadData`.

Both scripts attach `LD_PRELOAD` to the target binary only, via `env` at the
end of the chain — never `export` it for the whole script. The syscall-server
constructor ends with an unconditional `unsetenv("LD_PRELOAD")`
(`runtime/syscall-server/syscall_context.hpp`), so if a wrapper such as
`stdbuf` or `timeout` is preloaded first it wipes the variable and every
process it execs afterwards, including the loader, gets no gprobe at all. The
loader then talks to the real kernel, which rejects map type 1503 with
`-EINVAL`; the log shows a complete gprobe init (from the wrapper) but no
`SYS_BPF` / `Creating map type=` lines.

`libgprobe-agent.so` has no such `unsetenv`, so on the agent side the failure
mode is the opposite: it propagates into every wrapper and child, and each one
runs the agent constructor (3 init blocks / 3 pids measured with the old
export-based form). Keeping `LD_PRELOAD` off the wrappers avoids both.

### Note: GPU private memory per thread

MetaX budgets private (scratch) memory per thread from a fixed driver
carve-out, unlike AMDGPU where scratch is backed by VRAM:

```sh
cat /sys/module/metax/parameters/pri_mem_sz   # Kbyte per thread, default 4
```

The eBPF lifter reserves one 512-byte eBPF stack per BPF-to-BPF call level
(`vm/llvm-jit/src/compiler.cpp`: `STACK_SIZE * MAX_LOCAL_FUNC_DEPTH`). At the
default depth of 32 that is ~16 KB per thread, so an instrumented kernel used
to be rejected at launch with `mcErrorMemoryValueTooLarge` (32):

```
mc_platform.cpp:83: Error in allocating private memory ... The system is set
to :4 KB/Thread, kernel request:17 KB/thread
```

**This is now handled in the code**: `generateModule()` detects the
`mxc-metax` triple and uses `MACA_MAX_LOCAL_FUNC_DEPTH = 4` /
`MACA_CALL_STACK_SIZE = 8`, which brings `.private_memory_size` in the device
object down to 2144 bytes — comfortably inside the stock 4 KB budget. Other
triples (host JIT, AMDGPU, NVPTX) keep the original constants, so their
generated IR is unchanged.

The trade-off: BPF-to-BPF call nesting on MACA is limited to 4 levels. This
example's eBPF program makes no calls at all. A program nesting deeper would
overrun the reservation; note that `callItemCnt` has never been bounds-checked
on any target, so this is a budget change rather than a removed safeguard.

If you need deeper nesting on MACA, the alternative is raising the driver
budget instead. `pri_mem_sz` is read-only at runtime (`-r--r--r--`), so that
means reloading `metax.ko` with `pri_mem_sz=<Kbyte>` or setting it in
`/etc/modprobe.d/` and rebooting, with no other process using the GPU — and it
applies machine-wide to every workload on every card.

## CLI verification (maca-build)

See `/home/ll/docs-for-gprobe-develop/maca-build-verification-guide.md` and
`/home/ll/maca-verify/` for the end-to-end verification flows:

- GPU-execution level (minimal trampoline):
  `/home/ll/maca-verify/run_all.sh`
- Production build level (this example's bpf object + the full
  `attach/maca_attach_impl/trampoline/default_trampoline.maca`):
  `gprobe-vm maca-build --maca vec_add.maca \
      --ebpf .output/maca_simple_counter.bpf.o \
      --helper ../../../attach/maca_attach_impl/trampoline/default_trampoline.maca \
      --kernel _Z9vectorAddPKfS0_Pf --mcpu xcore1000 \
      --output /tmp/vec_add_modified.out`
