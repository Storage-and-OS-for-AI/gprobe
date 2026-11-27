# CUDA Graph eBPF Probe Example

This example shows how `gprobe` instruments kernels executed through CUDA Graphs.

- The CUDA app `vec_add_graph` builds a CUDA Graph containing a `vectorAdd` kernel and repeatedly launches it with `cudaGraphLaunch`.
- The eBPF program `cuda_probe` attaches to the `vectorAdd` kernel entry/exit points, even when the kernel is launched from a graph.

## Build

From the `gprobe/` repository root, build gprobe with CUDA attach enabled:

```bash
cmake -Bbuild -DGPROBE_ENABLE_CUDA_ATTACH=1 -DGPROBE_CUDA_ROOT=/usr/local/cuda .
cmake --build build -j"$(nproc)"
```

Build the example:

```bash
# or: export PATH=$GPROBE_CUDA_ROOT/bin:$PATH
make -C example/gpu/cudagraph
```

## Run

Open two terminals.

**Terminal 1 (server, loads eBPF program):**

```bash
GPROBE_LOG_OUTPUT=console GPROBE_GLOBAL_SHM_NAME=gprobe_maps_shm_graph \
LD_PRELOAD=build/runtime/syscall-server/libgprobe-syscall-server.so \
  example/gpu/cudagraph/cuda_probe
```

**Terminal 2 (client, runs CUDA Graph app):**

```bash
GPROBE_LOG_OUTPUT=console GPROBE_GLOBAL_SHM_NAME=gprobe_maps_shm_graph \
LD_PRELOAD=build/runtime/agent/libgprobe-agent.so \
  example/gpu/cudagraph/vec_add_graph
```
This will print the eBPF output from `cuda_probe` confirming the graph-launched kernel is being traced.
