# gprobe: eBPF-based GPU Program Observability

`gprobe` makes eBPF programs run **inside GPU kernels**. You describe what you
want to observe in plain C, gprobe intercepts the GPU runtime APIs of the target
process, compiles the probe and injects it into the device code — PTX injection
for NVIDIA, LLVM IR instrumentation for AMD and MetaX — and the probe then
executes on the GPU together with your kernel, publishing its findings through
BPF maps shared with the host.

CPU-side probes (uprobes on `cudaLaunchKernel`, on framework or driver entry
points) and GPU-side probes are peers in the same control plane and share the
same maps, so a launch event on the host and a block start event on the device
can be correlated directly.

📖 [Why](#why-gpu-observability) \
⚙️ [How It Works](#how-gprobe-works) \
📦 [Key Features](#key-features) \
🖥️ [Supported GPUs](#supported-gpus) \
🔬 [What You Can Observe](#what-you-can-observe) \
🧭 [Architecture](#architecture-and-core-components) \
🔨 [Quick Start](#quick-start) \
🌱 [Origins](#origins) \
📄 [License](#license)


## Why GPU Observability

### The GPU is the largest observability blind spot in AI infrastructure

As LLM training and inference became the dominant datacenter workload, the
interesting computation moved from the CPU into GPU kernels. The host side of
the stack is well covered: the application calls into PyTorch or vLLM, the CPU
runtime launches kernels, manages streams and schedules batches, and the GPU
executes them. But from the host you only ever see *what was submitted*, never
*how the GPU actually executed it*. Questions that decide whether an inference
service meets its SLO are invisible to CPU-side tooling:

- When did each block of this kernel actually start executing?
- Which SM did the scheduler place each block on, and is the placement balanced?
- Is there resource contention inside the GPU, and where?
- How are warps and threads progressing inside the kernel?

### Asynchronous execution destroys the timeline

CUDA/HIP applications are asynchronous by design: enqueuing work returns
immediately and only the final synchronization point blocks. Timing information
that used to be attached to individual API calls collapses into one number.

```text
CPU timeline (what host-side tools see)

  cudaMallocAsync         ~1 us   enqueue, returns immediately
  cudaMemcpyAsync         ~1 us   enqueue, returns immediately
  cudaLaunchKernel        ~1 us   enqueue, returns immediately
  cudaMemcpyAsync         ~1 us   enqueue, returns immediately
        ... the CPU keeps running, with no visibility into the device ...
  cudaStreamSynchronize  456 us   <- the only blocking call; every GPU phase
                                      collapses into this single number

GPU timeline (what actually happens, serialized inside the stream)

  alloc     |#|   ~1 us
  H->D DMA  |#####################################|  205 us
  kernel    |##################|  100 us
  D->H DMA  |###########################|  150 us
            (plus the launch overhead of each enqueue)
```

Every enqueue returns in about a microsecond; the single blocking call reports
456 μs of serialized GPU work (1 + 205 + 100 + 150 μs). With synchronous APIs,
measuring each call at least told you whether transfer or compute dominated. In
asynchronous mode that ability disappears: "is my bottleneck memory transfer or
kernel execution?" becomes unanswerable from the host.

Batching, multi-stream dependency graphs and persistent kernels — exactly the
optimizations production inference stacks rely on — make the phase boundaries
even harder to see, because a persistent kernel never returns and therefore
never produces a boundary event at all.

### What existing tools can and cannot do

**Boundary tracing** (LD_PRELOAD hooks on `libcuda.so`/`libamdhip64.so`, driver
or syscall interception) captures launches, transfers, synchronizations and API
timings. It treats the GPU as a black box: nothing about kernel-internal
execution, no warp-level behavior, no way to react to device-side state.

**Vendor profilers** (Nsight Systems/Compute, CUPTI, ROCProfiler, NVBit)
do reach inside the device, but with a different set of constraints:

1. A **closed event model** — a fixed set of events and counters, with no
   arbitrary programmable logic at the attach point .
2. **Session-based collection** — profiling sessions, counter multiplexing and
   kernel replay perturb the workload, so they are unsuitable for always-on
   production telemetry and routinely miss transient or rare events.
3. **No in-situ filtering or aggregation** — raw events are exported and
   post-processed, producing multi-GB traces instead of a counter or histogram
   computed on the device.
4. **No dynamic attach to running kernels** — a persistent kernel cannot be
   probed without restarting the process.
5. **Isolation from the Linux eBPF ecosystem** — no kprobe/uprobe/tracepoint
   integration and no data structures shared between CPU and GPU
   instrumentation, which makes it very hard to stitch a causal chain such as
   *host page fault → delayed enqueue → warp stall spike*.
6. **Cost** — fine-grained device instrumentation typically slows the kernel by
   one to two orders of magnitude.

Binary instrumentation frameworks such as NVBit provide instruction-level
visibility, but require writing SASS/PTX-level tooling directly, without eBPF's
safety verification, portability or toolchain.

CUPTI is excellent for kernel-level start/end times and hardware counters; it
does not tell you *why* a kernel was slow.

**gprobe does not replace these profilers.** It complements them where they are
structurally weakest: dynamic, always-on, programmable probing with correlated
CPU and GPU events.

## How gprobe Works

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ eBPF probes in C — SEC("kprobe/<device kernel>"), SEC("uprobe"), BPF maps  │
└───────────────────────────────────┬────────────────────────────────────────┘
                                    │ stock clang / libbpf toolchain, unchanged
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ gprobe Runtime (userspace only)                                            │
│   syscall-server : serves bpf() syscalls, owns progs/maps/links in shm     │
│   agent          : intercepts CUDA / HIP / MACA APIs, instruments device   │
│                    code, injects probes, shares memory with the GPU        │
│   vm/llvm-jit    : eBPF bytecode → host native code, and → device code     │
└───────────┬────────────────────────────────┬───────────────────────────────┘
            │ PTX injection                  │ LLVM IR instrumentation
            │ (NVIDIA CUDA)                  │ (AMD ROCm/HIP, MetaX MACA)
            ▼                                ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ GPU kernel + injected eBPF probe — runs per thread / per block on device   │
└───────────────────────────────────┬────────────────────────────────────────┘
                                    │ GPU array / ringbuf maps (zero copy)
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Host: read the same maps, aggregate, histogram, drive the control plane    │
└────────────────────────────────────────────────────────────────────────────┘
```

1. **Write** the probe in C with the standard eBPF toolchain (`clang -target bpf`,
   libbpf skeletons). Nothing GPU-vendor-specific in the probe source.
2. **Intercept**: the agent hooks the GPU runtime APIs of the target process
   (`__cudaRegisterFatBinary` / `cudaLaunchKernel` on NVIDIA,
   `hipLaunchKernel` / `hipModuleLaunchKernel` on AMD,
   `mcLaunchKernel` / `mcModuleLaunchKernel` on MetaX) and captures the device
   code before it reaches the driver.
3. **Compile**: `vm/llvm-jit` lifts the eBPF bytecode and generates device code —
   PTX for NVIDIA, LLVM IR for AMD and MetaX.
4. **Instrument and inject**: the probe is woven into the target kernel
   (entry / exit / memory-capture points), registers are saved and restored so
   the original kernel semantics are preserved, and the instrumented module is
   loaded in place of the original.
5. **Execute on the device**: the probe runs with the kernel, reading hardware
   context (`%smid`, `%warpid`, `%laneid`, `blockIdx`, `threadIdx`, global timer)
   through eBPF helpers.
6. **Share**: results land in GPU-resident or host-shared BPF maps that the
   loader reads without copying, so filtering, sampling and aggregation happen
   in situ instead of producing a trace.

## Key Features

- **Programmable observation.** You define what to collect in C — which kernels,
  which threads, which condition — instead of selecting from a fixed event catalog.
  Filter, sample and aggregate inside the probe; only the result crosses to the host.
- **Cross-layer CPU ↔ GPU correlation.** Host uprobes and device probes share
  maps and one control plane, so metrics that span the boundary become directly
  measurable — queueing delay per block, which host thread launched the kernel
  that diverged, whether a host-side stall shows up as a device-side gap.
- **Lightweight, dynamic and fine-grained.** Probes are loaded and unloaded at
  runtime(for NVIDIA GPUS); no application rebuild, no kernel or driver change, no profiling
  session. Device-side instrumentation overhead is significantly lower than
  comparable device instrumentation approaches, and warp-level granularity is
  available when you need it.
- **Zero-copy GPU maps.** `BPF_MAP_TYPE_GPU_ARRAY_MAP` (per-thread storage in
  device memory, DMA-visible to the host) and `BPF_MAP_TYPE_GPU_RINGBUF_MAP`
  (lock-free per-thread event streaming) give high-throughput collection without
  a host round trip per event.
- **Vendor-neutral probe model.** One eBPF programming interface; the vendor
  differences (device code representation, instrumentation backend, timer
  semantics) are confined to the attach layer.

### GPU eBPF helpers

| Helper ID | Function | Description |
|-----------|----------|-------------|
| 501 | `ebpf_puts(const char *)` | Print a string from the device to the host console |
| 502 | `bpf_get_globaltimer(void)` | Device global timer |
| 503 | `bpf_get_block_idx(u64 *x, u64 *y, u64 *z)` | `blockIdx` |
| 504 | `bpf_get_block_dim(u64 *x, u64 *y, u64 *z)` | `blockDim` |
| 505 | `bpf_get_thread_idx(u64 *x, u64 *y, u64 *z)` | `threadIdx` |
| 506 | `bpf_gpu_membar(void)` | Device memory barrier (`membar.sys`) |
| 508 | `bpf_get_grid_dim(u64 *x, u64 *y, u64 *z)` | `gridDim` |
| 509 | `bpf_get_sm_id(void)` | Streaming Multiprocessor executing this thread |
| 510 | `bpf_get_warp_id(void)` | Warp ID within the SM |
| 511 | `bpf_get_lane_id(void)` | Lane ID (0–31) within the warp |

Standard helpers such as `bpf_map_lookup_elem`, `bpf_map_update_elem`,
`bpf_perf_event_output`, `bpf_trace_printk` and `bpf_get_current_pid_tgid` also
work on the device: map operations on GPU maps stay entirely device-side,
everything else goes through a shared-memory protocol to the host.

## Supported GPUs

| Platform | Instrumentation | Status |
|----------|-----------------|--------|
| NVIDIA CUDA | PTX injection | End-to-end verified: dynamic PTX injection, in-kernel probe execution, CPU/GPU shared data |
| AMD ROCm / HIP | LLVM IR instrumentation | End-to-end verified: IR instrumentation, device-side observation of HIP programs |
| MetaX MACA | LLVM IR instrumentation | End-to-end verified: IR instrumentation, in-kernel probe execution, CPU/GPU shared map |

More vendors are planned. The probe source is the same across all of them; only
the attach backend differs.

## What You Can Observe

### Case 1 — Block-level kernel launch latency (cross-layer correlation)

[`example/gpu/launchlate`](example/gpu/launchlate) measures the gap between a
kernel being submitted on the host and each of its blocks actually starting on
the device. A CPU-side uprobe timestamps `cudaLaunchKernel()`; a device-side
probe timestamps kernel entry per block; the difference is binned into a
histogram that lives in a GPU array map.

```c
/* CPU side: host submits the kernel */
SEC("uprobe")
int BPF_KPROBE(uprobe_cuda_launch, const void *func, u64 gridDim, u64 blockDim)
{
	u64 ts_cpu = bpf_ktime_get_ns();
	u32 key = 0;
	s64 *offset = bpf_map_lookup_elem(&clock_offset, &key);
	if (offset)
		ts_cpu += *offset;                 /* align the two clock domains */
	bpf_map_update_elem(&last_uprobe_time, &key, &ts_cpu, BPF_ANY);
	return 0;
}

/* GPU side: injected at kernel entry, executes on the device */
SEC("kprobe/_Z9vectorAddPKfS0_Pf")
int cuda__probe()
{
	u64 gpu_ts = bpf_get_globaltimer();        /* when this block starts */
	u32 key = 0;
	u64 *uprobe_ts = bpf_map_lookup_elem(&last_uprobe_time, &key);
	if (uprobe_ts && *uprobe_ts > 0) {
		u64 delta_ns = gpu_ts > *uprobe_ts ? gpu_ts - *uprobe_ts : 0;
		u32 bin = get_hist_bin(delta_ns);
		u64 *count = bpf_map_lookup_elem(&time_histogram, &bin);
		if (count)
			*count += 1;                   /* aggregate in situ, on the GPU */
	}
	return 0;
}
```

```text
Clock calibration: REALTIME - MONOTONIC = 1625284901234 ns

Monitoring CUDA kernel launch latency... Hit Ctrl-C to end.

12:34:56 Launch Latency Distribution:
latency         : count    distribution
100ns-1us       : 45       |********
1-10us          : 234      |****************************************
10-100us        : 167      |*****************************
100us-1ms       : 89       |***************
1-10ms          : 12       |**
Total samples: 547
```

Why block granularity matters: a kernel-level start/end pair hides the fact
that under multi-process or multi-stream load, blocks start in waves because of
stream dependencies and SM contention. Block-level timestamps expose the
spread, the stragglers and how the distribution shifts between runs.

> **What ΔT actually measures.** `ΔT = T_device − T_host` is the *end-to-end
> observed* latency from host submission to the moment a block runs the probe.
> It includes runtime overhead, driver overhead, stream dependency waits, SM
> resource contention and GPU scheduling delays — it is not pure SM queue time.
> `bpf_ktime_get_ns()` and `bpf_get_globaltimer()` come from different clock
> sources, so the two domains must be calibrated before subtraction (the example
> does this at startup and stores the offset in a map); over long runs, drift
> may require recalibration.

This turns previously hidden GPU launch delays into measurable latency distributions: how much time do kernels spend waiting between host submission and device execution, do launch overheads dominate the execution time of short-lived kernels, do occasional latency spikes contribute to long-tail performance, and how do stream dependencies and resource contention affect kernel launch latency under different workload conditions?

### Case 2 — SM / warp / thread placement inside the kernel

[`example/gpu/threadscheduling`](example/gpu/threadscheduling) attaches a device
probe that reads `%smid`, `%warpid` and `%laneid` for every thread and builds the
thread → hardware mapping, which the host renders as SM utilization, per-SM warp
distribution and a load-balance score.

```text
┌─ SM Utilization Histogram ─────────────────────────────────────────┐
│  SM 110: ################################            321 threads   │
│  SM 111: ##########################################  415 threads   │
│  SM 112: ####################################        355 threads   │
│  SM 113: #############################               292 threads   │
│                                                                    │
│  Total threads: 1383     Active SMs: 4     Load balance: 4.0%      │
└────────────────────────────────────────────────────────────────────┘

┌─ Warp Distribution per SM ─────────────────────────────────────────┐
│  SM    │ Warp ID │ Thread Count                                    │
├────────────────────────────────────────────────────────────────────┤
│  110   │    0    │      222                                        │
│  110   │    1    │      12                                         │
│  111   │    0    │      38                                         │
│  111   │    1    │      129                                        │
│  112   │    0    │      176                                        |  
|  ...                                                               |
└────────────────────────────────────────────────────────────────────┘
```

The load-balance score is a statistic computed by the example (100% = perfectly
even thread distribution across the active SMs); it describes this particular
launch configuration, not GPU hardware utilization.

Use it to:

- **Inspect the scheduler's block placement** — which SMs your blocks and threads
  actually land on.
- **Detect imbalance** — a few SMs carrying most of the threads while others idle.
- **Validate kernel configuration** — compare block/warp configurations against
  the mapping they produce, and tune grid dimensions accordingly.
- **Debug persistent kernels** — a persistent design typically launches one block
  per SM and expects each block to own a distinct SM. That assumption is not
  observable from the host at all; here you can verify the mapping and watch the
  resident blocks draw work over time.

## Architecture and Core Components

```text
┌────────────────────────────────┐                ┌────────────────────────────────┐
│ Loader / control plane         │ shared BPF     │ Target GPU application         │
│ (your eBPF program, e.g.       │◀──────────────▶│ (vLLM, PyTorch, your .cu /     │
│  launchlate)                   │ maps           │  .hip / .maca binary)          │
│ libgprobe-syscall-server.so    │                │ libgprobe-agent.so             │
└──────────────┬─────────────────┘                └──────────────┬─────────────────┘
               │                                                 │
               ▼                                                 ▼
      vm/llvm-jit:                                    attach backend:
      eBPF bytecode → host code                       nv / rocm / maca — GPU API
      and → device code                               interception, PTX injection,
                                                      LLVM IR instrumentation
               │                                                 │
               └─────────────────────────┬───────────────────────┘
                                         ▼
          instrumented GPU kernel: the probe runs on the device alongside your
          kernel and writes into the maps the loader reads back
```

### `server` — `libgprobe-syscall-server.so` ([runtime/syscall-server](runtime/syscall-server))

The control plane, preloaded into your loader process. It serves `bpf()`
syscalls in userspace, so an unmodified libbpf program (open / load / attach /
skeleton) talks to gprobe instead of the kernel. It owns programs, maps and
links in a shared-memory registry addressed by file-descriptor-like handles,
runs host-side eBPF programs, and
reads back the data the device probes produce for aggregation and display.

### `agent` — `libgprobe-agent.so` ([runtime/agent](runtime/agent))

Injected into the target GPU process, either by `LD_PRELOAD` at start or
dynamically into a running process with `gprobe attach <pid>`. Inside the host
process it intercepts the GPU runtime APIs, captures device code as it is
registered, drives instrumentation and probe injection for the selected vendor
backend, and registers the shared-memory segment with the GPU (`cudaHostRegister`
/ `hipHostRegister` / MACA equivalent) so device code can dereference host map
pointers directly. 

### `vm/llvm-jit` ([vm/llvm-jit](vm/llvm-jit))

The LLVM-based JIT/AOT eBPF compiler. It turns eBPF bytecode into optimized host
machine code for the CPU-side probes, and into device code for the GPU-side
probes — PTX with automatic compute-capability detection for NVIDIA, and the
LLVM IR instrumentation used by the AMD and MetaX backends. It can also be built as a
standalone library or AOT compiler independent of gprobe.

### Attach backends ([attach](attach))

`nv_attach_impl` (CUDA, PTX injection), `rocm_attach_impl` (ROCm/HIP, LLVM IR
instrumentation) and `maca_attach_impl` (MetaX MACA, LLVM IR instrumentation)
share the same `base_attach_impl` interface and the same probe programming model,
and each provides its own device-side helper trampoline. Adding a vendor means
adding a backend, not rewriting the probes.

## Quick Start

### Prerequisites

```bash
sudo apt-get update && sudo apt-get install -y \
    libelf1 libelf-dev zlib1g-dev make cmake git libboost-all-dev \
    binutils-dev libyaml-cpp-dev ca-certificates clang llvm llvm-dev pkg-config
git submodule update --init --recursive
```

On rpm-based distributions install the `-devel` equivalents
instead — for example `boost-devel`, `elfutils-libelf-devel`, `zlib-devel`,
`binutils-devel`, `yaml-cpp-devel`, `clang`, `llvm-devel`. 

Recommended: `gcc` >= 12, `clang` >= 16, LLVM >= 15 (LLVM 18 for the ROCm
pipeline), CMake >= 3.15. Plus the vendor stack for your GPU: CUDA Toolkit 12.x,
ROCm 6.x at `/opt/rocm`, or the MACA SDK at `/opt/maca`.

### Build for NVIDIA CUDA

```bash
cmake -Bbuild -DCMAKE_BUILD_TYPE=Release \
    -DGPROBE_ENABLE_CUDA_ATTACH=1 \
    -DGPROBE_CUDA_ROOT=/usr/local/cuda-12.8
cmake --build build -j$(nproc)
```

`GPROBE_CUDA_ROOT` must point at your CUDA installation (e.g. `/usr/local/cuda-12.6`).
There is also a `make build-gpu` shortcut in the [Makefile](Makefile).

### Build for AMD ROCm / HIP

```bash
cmake -Bbuild -DCMAKE_BUILD_TYPE=Release \
    -DGPROBE_LLVM_JIT=1 \
    -DGPROBE_ENABLE_ROCM_ATTACH=ON -DGPROBE_ROCM_ROOT=/opt/rocm \
    -DBUILD_LLVM_HIP_CLI=ON \
    -DGPROBE_ENABLE_FRIDA=ON -DLLVM_DIR=/usr/lib/llvm-18/cmake
cmake --build build -j$(nproc)
```

### Build for MetaX MACA

```bash
cmake -Bbuild -DCMAKE_BUILD_TYPE=Release \
    -DGPROBE_LLVM_JIT=1 \
    -DGPROBE_ENABLE_MACA_ATTACH=ON -DGPROBE_MACA_ROOT=/opt/maca \
    -DBUILD_LLVM_MACA_CLI=ON \
    -DENABLE_LLVM_SHARED=ON \
    -DLLVM_DIR=/opt/llvm-15/lib/cmake/llvm \
    -DCMAKE_C_COMPILER=/opt/gcc-12/bin/gcc \
    -DCMAKE_CXX_COMPILER=/opt/gcc-12/bin/g++
cmake --build build -j$(nproc) \
    --target gprobe-agent gprobe-syscall-server maca-pipeline-helper
```

To use the `gprobe` CLI (`gprobe attach`, `gprobe trace`, ...) instead of raw
`LD_PRELOAD`, install it and put it on your `PATH`:

```bash
cmake --build build --target install
export PATH=$PATH:~/.gprobe
```

### Example: measure CUDA kernel launch latency

[`example/gpu/launchlate`](example/gpu/launchlate) combines a host uprobe on
`cudaLaunchKernel` with a device probe at kernel entry and prints a launch
latency histogram.

```bash
# 1. build the example (gprobe must already be built with CUDA attach enabled)
make -C example/gpu/launchlate
```

```bash
# 2. terminal 1 — control plane + loader: reads the target ELF, resolves
#    cudaLaunchKernel, loads the eBPF object, calibrates the clocks and prints
#    the histogram
GPROBE_LOG_OUTPUT=console \
LD_PRELOAD=build/runtime/syscall-server/libgprobe-syscall-server.so \
  example/gpu/launchlate/launchlate example/gpu/launchlate/vec_add
```

```bash
# 3. terminal 2 — the target CUDA application with the agent injected; the agent
#    instruments the kernels it registers and runs the device probe on the GPU
GPROBE_LOG_OUTPUT=console \
LD_PRELOAD=build/runtime/agent/libgprobe-agent.so \
  example/gpu/launchlate/vec_add
```

Output looks like:

```text
Clock calibration: REALTIME - MONOTONIC = 1625284901234 ns
  MONOTONIC: 3842.123456789
  REALTIME:  1625288743.357890890

Monitoring CUDA kernel launch latency... Hit Ctrl-C to end.

12:34:56 Launch Latency Distribution:
latency         : count    distribution
100ns-1us       : 45       |********
1-10us          : 234      |****************************************
10-100us        : 167      |*****************************
100us-1ms       : 89       |***************
1-10ms          : 12       |**
Total samples: 547
```

To trace your own kernel, point the device probe at its symbol:

```c
SEC("kprobe/_Z15yourKernelNamePfS_")   /* cuobjdump -symbols your_app | grep your_kernel */
```

### More examples

- NVIDIA: [launchlate](example/gpu/launchlate) (launch latency),
  [threadscheduling](example/gpu/threadscheduling) (SM / warp / thread mapping),
  [kernelretsnoop](example/gpu/kernelretsnoop) (per-thread exit timestamps),
  [threadhist](example/gpu/threadhist) (per-thread execution histogram),
  [mem_trace](example/gpu/mem_trace) (memory access tracing) — see
  [example/gpu](example/gpu) for the full list.
- AMD ROCm: [rocm-counter-two-probe](example/gpu/rocm-counter-two-probe) and
  [rocm_simple_counter](example/gpu/rocm_simple_counter).
- MetaX MACA: [maca_simple_counter](example/gpu/maca_simple_counter).

More examples for NVIDIA, AMD and MetaX are in development.

## Origins

gprobe originates from [bpftime](https://github.com/eunomia-bpf/bpftime), The
upstream copyright notice is preserved in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

## License

This project is licensed under the Apache License 2.0. See
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) for the original copyright and
license notices.
