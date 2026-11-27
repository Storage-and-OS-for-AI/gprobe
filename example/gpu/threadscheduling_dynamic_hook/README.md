# Thread Scheduling (Dynamic Hook) Example

This example demonstrates how to use gprobe's GPU eBPF tracing to map CUDA threads to their hardware execution units: Streaming Multiprocessors (SMs), warps, and lanes.

## Overview

The example consists of two main components:

1. **Vector Addition CUDA Application** (`vec_add`): A simple CUDA application that repeatedly performs vector addition on the GPU.

2. **eBPF CUDA Probe** (`threadscheduling`): An eBPF program that attaches to CUDA kernel functions, monitoring their execution and thread scheduling.

When CUDA kernels execute, the GPU scheduler assigns thread blocks to Streaming Multiprocessors (SMs). Within each SM, threads are grouped into warps of 32 threads that execute in lockstep.

## GPU Hardware Concepts

| Concept | Description | PTX Register |
|---------|-------------|--------------|
| **SM (Streaming Multiprocessor)** | Physical processing unit on the GPU. Multiple SMs run in parallel. | `%smid` |
| **Warp** | A group of 32 threads that execute in lockstep on an SM. | `%warpid` |
| **Lane** | A thread's position (0-31) within its warp. | `%laneid` |

## eBPF Helpers

This example uses three GPU eBPF helpers:

| Helper ID | Function | Description |
|-----------|----------|-------------|
| 509 | `bpf_get_sm_id()` | Returns the SM ID executing this thread |
| 510 | `bpf_get_warp_id()` | Returns the warp ID within the SM |
| 511 | `bpf_get_lane_id()` | Returns the lane ID (0-31) within the warp |

This directory is a dynamic-hook-friendly variant of `example/gpu/threadscheduling/`.

Key difference: `vec_add` passes `N` as a kernel argument (instead of `__constant__`)
to avoid relying on constant/global mirroring during late attach.

## Building the Example

```bash
# From the gprobe root directory, build with CUDA support
cmake -Bbuild -DGPROBE_ENABLE_CUDA_ATTACH=1 -DGPROBE_CUDA_ROOT=/usr/local/cuda .
make -C build -j$(nproc)

# Build this example
make -C example/gpu/threadscheduling_dynamic_hook
```

## Running the Example

You can run this example in two ways:

### Option A (Legacy): Preload at process start

You need two terminals:

#### Terminal 1: Launch the eBPF Program (Loader)

```bash
GPROBE_LOG_OUTPUT=console LD_PRELOAD=build/runtime/syscall-server/libgprobe-syscall-server.so \
  example/gpu/threadscheduling_dynamic_hook/threadscheduling
```

#### Terminal 2: Run the CUDA Application (Client, preloaded agent)

```bash
GPROBE_LOG_OUTPUT=console LD_PRELOAD=build/runtime/agent/libgprobe-agent.so \
  example/gpu/threadscheduling_dynamic_hook/vec_add [num_blocks] [threads_per_block]
```

Optional arguments:
- `num_blocks`: Number of thread blocks (default: 4)
- `threads_per_block`: Threads per block (default: 64)

Example with custom configuration:
```bash
# Run with 8 blocks and 128 threads per block
LD_PRELOAD=build/runtime/agent/libgprobe-agent.so \
  example/gpu/threadscheduling_dynamic_hook/vec_add 8 128
```

### Option B (Dynamic Attach): Start probing after the target has been running

This mode demonstrates "late attach":

- Start `vec_add` normally (no `LD_PRELOAD`)
- Let it run for ~5 seconds
- Start the probe, which will:
  - Run the loader (`threadscheduling`) with `gprobe-server` injected
  - Dynamically inject `gprobe-agent` into the already running `vec_add` process
  - Discover links incrementally (`--auto-refresh-ms`) so load/attach ordering isn't fragile

#### Terminal 1: Start the target (no preload)

```bash
example/gpu/threadscheduling_dynamic_hook/vec_add 4 64
```

Find the PID (in another shell):

```bash
pidof vec_add
```

#### Terminal 2: Start probing late

```bash
sudo GPROBE_LOG_OUTPUT=console ./build/tools/cli/gprobe trace --pidof vec_add --auto-refresh-ms 500 \
  example/gpu/threadscheduling_dynamic_hook/threadscheduling
```

Notes:
- Requires `GPROBE_ENABLE_CUDA_ATTACH=1` build.
- Requires privileges for process injection (typically `sudo`).
- Some environments enforce ptrace restrictions (e.g., yama `ptrace_scope=1`).
  `vec_add` can opt-in by setting `GPROBE_ALLOW_PTRACE=1`, which calls
  `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` to allow injection. This makes the
  target ptraceable by **any** process; only enable it in CI or otherwise
  isolated environments.
- `gprobe trace` will run the loader as the target process `uid/gid` (even if `gprobe` itself runs under `sudo`), to avoid shared-memory permission issues.
- For dynamic attach, `gprobe trace` will run `cuobjdump --extract-ptx all /proc/<pid>/exe` before injection and pass that PTX directory to the injected agent (so the agent doesn't need to spawn `cuobjdump` inside the target process).
  - If `cuobjdump` isn't in `PATH`, set `GPROBE_CUOBJDUMP=/path/to/cuobjdump` or `GPROBE_CUDA_ROOT=/usr/local/cuda-XX.Y`.
- If the target uses a non-zero GPU, set `GPROBE_CUDA_DEVICE=<idx>` for the agent/bootstrap to prefer that device (otherwise it will try to auto-detect/probe).
- `gprobe` will auto-detect libraries from the build tree; `cmake --install build` also works.

## Understanding the Output

The probe displays:

### SM Utilization Histogram
Shows how threads are distributed across SMs:
```
┌─ SM Utilization Histogram ─────────────────────────────────────────┐
│  SM  0: ████████████████████████████████████████     64 threads    │
│  SM  1: ████████████████████████████████████████     64 threads    │
│  SM  2: ████████████████████████████████████████     64 threads    │
│  SM  3: ████████████████████████████████████████     64 threads    │
│                                                                    │
│  Total threads: 256       Active SMs: 4                            │
└────────────────────────────────────────────────────────────────────┘
```

### Warp Distribution per SM
Shows which warps are active on each SM:
```
┌─ Warp Distribution per SM ─────────────────────────────────────────┐
│  SM   │ Warp ID │ Thread Count                                     │
├───────┼─────────┼──────────────────────────────────────────────────┤
│    0  │     0   │       32                                         │
│    0  │     1   │       32                                         │
│    1  │     0   │       32                                         │
│    1  │     1   │       32                                         │
└───────┴─────────┴──────────────────────────────────────────────────┘
```

### Thread-to-Hardware Mapping Samples
Shows individual thread assignments:
```
┌─ Thread-to-Hardware Mapping Samples ───────────────────────────────┐
│  Block(x,y,z)  │ Thread(x,y,z) │  SM  │ Warp │ Lane │              │
├────────────────┼───────────────┼──────┼──────┼──────┼──────────────┤
│  (  0, 0, 0)   │  (  0, 0, 0)  │    2 │    0 │    0 │              │
│  (  0, 0, 0)   │  ( 31, 0, 0)  │    2 │    0 │   31 │              │
│  (  1, 0, 0)   │  (  0, 0, 0)  │    5 │    0 │    0 │              │
└────────────────┴───────────────┴──────┴──────┴──────┴──────────────┘
```

### Load Balance Score
A percentage indicating how evenly threads are distributed across SMs:
- 100% = perfect distribution (all SMs have equal load)
- Lower values indicate imbalanced distribution

## Use Cases

### 1. Verify Block-to-SM Distribution
Run with different block counts to see how the GPU scheduler distributes work:
```bash
# Few blocks - may not use all SMs
./vec_add 2 64

# Many blocks - should distribute across all SMs
./vec_add 16 64
```

### 2. Debug Persistent Kernels
For persistent kernel designs (one block per SM), verify each block maps to a unique SM by running one block per SM:

Number of SMs varies by GPU, so you will adjust your `block` size accordingly:
```bash
# Example for RTX 3090 (82 SMs)
./vec_add 82 64

# Example for RTX 4090 (128 SMs)
./vec_add 128 64
```

### 3. Analyze Warp Occupancy
Check how warps are distributed within blocks:
```bash
# 128 threads = 4 warps per block
./vec_add 4 128

# 256 threads = 8 warps per block
./vec_add 4 256
```

## Implementation Details

The eBPF probe (`threadscheduling.bpf.c`) attaches to the `vectorAdd` CUDA kernel and:

1. Reads hardware scheduling registers via helpers 509-511
2. Records thread-to-hardware mapping in a BPF hash map
3. Maintains SM and warp histograms for analysis
4. Outputs debug information for the first thread of each warp

The userspace loader (`threadscheduling.c`) periodically:

1. Reads the BPF maps
2. Computes statistics and histograms
3. Displays the mapping visualization
