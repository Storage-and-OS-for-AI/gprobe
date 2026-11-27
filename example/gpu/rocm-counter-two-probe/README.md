# ROCm eBPF Two-Probe Example (kprobe + kretprobe on One Kernel)

This is the ROCm counterpart of `example/gpu/cuda-counter`: a single eBPF
object containing a kprobe and a kretprobe attached to the same HIP kernel
(`_Z9vectorAddPKfS0_Pf`), verifying that both probes coexist in one
instrumented hsaco.

The eBPF program names carry the `rocm__` prefix (`rocm__probe` /
`rocm__retprobe`) so the agent routes them to `rocm_attach_impl` — the same
convention `cuda-counter` uses with `cuda__` on the NVIDIA side.

## Build

Build gprobe with ROCm attach support first:

```sh
cmake -Bbuild -DGPROBE_LLVM_JIT=1 -DBUILD_LLVM_HIP_CLI=ON \
    -DGPROBE_ENABLE_ROCM_ATTACH=ON -DGPROBE_ROCM_ROOT=/opt/rocm \
    -DGPROBE_ENABLE_FRIDA=ON -DLLVM_DIR=/usr/lib/llvm-18/cmake
cmake --build build --target gprobe-agent gprobe-syscall-server \
    hip-pipeline-helper -j
```

Then build this example:

```sh
make -C example/gpu/rocm-counter-two-probe CLANG=clang-18
```

## Run

Terminal 1 — start the server (loader):

```sh
cd /home/lz/gprobe
pkill -9 -f "rocm_two_probe|vec_add|hip-pipeline" 2>/dev/null
rm -f /dev/shm/gprobe_maps_shm /tmp/gprobe-shm-gprobe_maps_shm.lock

GPROBE_LOG_OUTPUT=console \
LD_PRELOAD=build/runtime/syscall-server/libgprobe-syscall-server.so \
example/gpu/rocm-counter-two-probe/rocm_two_probe
```

Terminal 2 — start the agent (target GPU program):

```sh
cd /home/lz/gprobe
SPDLOG_LEVEL=info GPROBE_LOG_OUTPUT=console \
GPROBE_ROCM_HIP_SOURCE=example/gpu/rocm-counter-two-probe/vec_add.hip \
LD_PRELOAD=build/runtime/agent/libgprobe-agent.so \
example/gpu/rocm-counter-two-probe/vec_add
```

## Expected Output

Agent side (stderr): the shared memory segment is registered with HIP,
then the second attach regenerates the hsaco so a single instrumented
kernel hosts both probes:

```
Registered shared memory with ROCM: addr=0x76a399a00000 size=52428800
CommSharedMem already covered by the whole-segment registration
rocm_attach_impl: attach id 1 -> kernel _Z9vectorAddPKfS0_Pf (1 probe(s))
rocm_attach_impl: instrumented kernel _Z9vectorAddPKfS0_Pf ready
rocm_attach_impl: attach id 2 -> kernel _Z9vectorAddPKfS0_Pf (2 probe(s))
rocm_attach_impl: replaced instrumented kernel _Z9vectorAddPKfS0_Pf (2 probe(s) active)
Attach successfully
```

Server side (stdout): `call_count` (incremented by the kprobe via
`__atomic_add_fetch`) grows by 10 per second — the block runs 10 threads
and each thread's probe atomically adds 1. The first sample may show 1
(the value inserted by the first launch before the remaining atomic adds
land):

```
15:47:57
	pid=12345 	calls: 1
	pid=12345 	total_time: 2900128
15:47:58
	pid=12345 	calls: 11
	pid=12345 	total_time: 17401053
15:47:59
	pid=12345 	calls: 21
	pid=12345 	total_time: 32186354
...
```

`total_time` (accumulated by the kretprobe via `__atomic_add_fetch`) grows
as well — in `clock64()` cycles, see the third note below.

Target program (stdout):

```
qwq
counter = 233 (expected 234)
C[0] = 0 (expected 0)
C[1] = 3 (expected 3)
```

`qwq` comes from `test_kernel_2` (device `printf`); `counter` stays at 233
while `expected` keeps growing — see the second note below.

## Notes

- The hash-map values live in the gprobe shared memory segment. The agent
  registers the whole segment with `hipHostRegister` so the GPU can
  dereference the pointers returned by `bpf_map_lookup_elem` (mirroring the
  CUDA side, where the whole segment is registered with
  `cudaHostRegister`).
- `test_kernel_2` is launched every second as well, but is not instrumented:
  it verifies that kernel launches without an attached probe pass through
  the `hipLaunchKernel` hook untouched. Its `counter` writes go to the
  original module, while `hipMemcpyFromSymbol` is mirrored to the
  instrumented module's copy, so the printed `counter` stays at the value
  last written via `hipMemcpyToSymbol` (233). This mirrors the CUDA-side
  read-mirror semantics for non-instrumented kernels.
- `bpf_get_globaltimer` (helper 502) returns `clock64()` GPU cycles on
  AMDGPU, so `total_time_ns` counts cycles rather than nanoseconds. It is
  a per-CU counter, so the `duration` printed by the return probe can
  wrap around when the entry and exit reads come from different CU
  counters.
- This example is structurally identical to `cuda_probe.bpf.c` except for
  the `rocm__` program-name prefix and **three deliberate fixes** for bugs
  carried in the CUDA original (kept unfixed there):
  1. `bpf_map_delete_elem(&start_ts, &x)` — the original deletes with
     `&pid` while the insert uses `&x`, so the delete never matches and
     the entry silently leaks; here the entry is consumed per launch and
     re-inserted by the next kprobe.
  2. The `total_time_ns` accumulation uses
     `__atomic_add_fetch(total, delta, SEQ_CST)` — the original does a
     non-atomic `*total += delta` (concurrent threads lose updates) and
     then rewrites the same value through a redundant
     `bpf_map_update_elem(BPF_EXIST)` RPC.
  3. The loader also prints `total_time_ns` — in the original nobody ever
     reads that map, so the accumulated durations stay invisible.
