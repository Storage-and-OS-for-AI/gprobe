# ROCm eBPF Simple Counter Example (Single kprobe)

The minimal ROCm GPU eBPF example: a single eBPF program with one kprobe
attached to a HIP kernel (`_Z9vectorAddPKfS0_Pf`), incrementing a counter
map entry on every launch. It exercises the GPU array map fast path — the
map lookup runs entirely on the device and never round-trips to the host.

The eBPF program name carries the `rocm__` prefix
(`rocm__trace_rocm_kernel`) so the agent routes it to `rocm_attach_impl`.

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
make -C example/gpu/rocm_simple_counter CLANG=clang-18
```

If `vec_add` fails to build with
`use of undeclared identifier '__AMDGCN_WAVEFRONT_SIZE'`, a stale
system-wide `/usr/include/hip` installation is shadowing the ROCm headers.
Build it with the ROCm include path explicitly (the same recipe
`rocm-counter-two-probe` uses in its Makefile):

```sh
hipcc -isystem "$(dirname "$(dirname "$(command -v hipcc)")")/include" \
    vec_add.hip -o vec_add -g
```

## Run

Terminal 1 — start the server (loader):

```sh
cd /home/lz/gprobe
pkill -9 -f "rocm_simple_counter|vec_add|hip-pipeline" 2>/dev/null
rm -f /dev/shm/gprobe_maps_shm /tmp/gprobe-shm-gprobe_maps_shm.lock

GPROBE_LOG_OUTPUT=console \
LD_PRELOAD=build/runtime/syscall-server/libgprobe-syscall-server.so \
example/gpu/rocm_simple_counter/rocm_simple_counter
```

Terminal 2 — start the agent (target GPU program):

```sh
cd /home/lz/gprobe
SPDLOG_LEVEL=info GPROBE_LOG_OUTPUT=console \
GPROBE_ROCM_HIP_SOURCE=example/gpu/rocm_simple_counter/vec_add.hip \
LD_PRELOAD=build/runtime/agent/libgprobe-agent.so \
example/gpu/rocm_simple_counter/vec_add
```

## Expected Output

Agent side (stderr): the shared memory segment is registered with HIP,
then the single attach produces the instrumented kernel (no replacement —
only one probe targets this kernel):

```
Registered shared memory with ROCM: addr=0x7410c7c00000 size=52428800
CommSharedMem already covered by the whole-segment registration
rocm_attach_impl: attach id 1 -> kernel _Z9vectorAddPKfS0_Pf (1 probe(s))
rocm_attach_impl: instrumented kernel _Z9vectorAddPKfS0_Pf ready
Attach successfully
```

Server side (stdout): `counter[0]` stays 0 while the agent initializes,
then grows by 1 per second (one launch per second):

```
counter[0]=0
counter[0]=0
counter[0]=1
counter[0]=2
counter[0]=3
...
```

Target program (stdout):

```
C[0] = 0 (expected 0)
C[1] = 3 (expected 3)
```

## Notes

- The `counter` map is a `BPF_MAP_TYPE_GPU_ARRAY_MAP` (type 1503): the
  server allocates it in GPU memory (`hipMalloc` +
  `hipIpcGetMemHandle`) and shares it with the agent, so the trampoline's
  `bpf_map_lookup_elem` resolves it entirely device-side
  (`extra_buffer + key * value_size`) without any host round trip. The
  server reads the counter back with `hipMemcpy`.
- The kernel runs with a block of 10 threads and the probe updates the
  value non-atomically (`*val = *val + 1`). The threads execute in
  lockstep, so they all read the same old value and write old+1 — the net
  effect is exactly +1 per launch.
- `C[1] = 3` requires the `__constant__` variable `d_N` to be mirrored
  into the instrumented module: the kernel guards every element with
  `if (idx < d_N)`, and the `hipMemcpyToSymbol` hook copies the write to
  the instrumented module's copy of the constant.
