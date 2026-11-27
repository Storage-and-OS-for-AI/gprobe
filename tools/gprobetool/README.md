# gprobetool

Command-line tool for inspecting and managing gprobe shared memory state.

## Overview

`gprobetool` provides utilities to:
- **Export** shared memory state to JSON for inspection or backup
- **Import** eBPF objects from JSON into shared memory
- **Run** eBPF programs with performance benchmarking
- **Remove** shared memory segments system-wide

## Installation

After building gprobe, the tool is available at:
```bash
~/.gprobe/gprobetool
# Or add to PATH
export PATH=$PATH:~/.gprobe/
```

## Command Reference

### export - Dump Shared Memory to JSON

Export all eBPF objects (programs, maps, links) from shared memory to a JSON file:

```bash
gprobetool export <filename>
```

**Example:**
```console
$ gprobetool export state.json
[info] Global shm constructed. shm_open_type 1 for gprobe_maps_shm
[info] bpf_map_handler name=.rodata.str1.1 found at 3
[info] find prog fd=4 name=do_uprobe_trace
[info] bpf_perf_event_handler found at 5
```

The JSON file contains:
- eBPF program bytecode and metadata
- Map definitions and attributes
- Perf event attachments
- Handler file descriptors

**Use cases:**
- Debugging runtime state
- Backup before modifications
- Analysis and reverse engineering
- Sharing test cases

### import - Load JSON into Shared Memory

Import eBPF objects from a JSON file into gprobe shared memory:

```bash
gprobetool import <filename>
```

**Example:**
```console
$ SPDLOG_LEVEL=Debug gprobetool import minimal.json
[info] Global shm constructed. shm_open_type 3 for gprobe_maps_shm
[info] import handler fd 3 {"attr":{...},"name":".rodata.str1.1","type":"bpf_map_handler"}
[info] import handler type bpf_prog_handler fd 4
[info] import handler type bpf_perf_event_handler fd 5
```

**Use cases:**
- Restore previous state
- Load pre-configured environments
- Testing and CI/CD pipelines
- Cross-system deployment

### run - Execute and Benchmark Programs

Run an eBPF program from shared memory with performance measurement:

```bash
gprobetool run <id> <data_file> [repeat N] [type RUN_TYPE]

Arguments:
  id          Program ID in shared memory
  data_file   Input data file (program context)

Options:
  repeat N           Run N times and report average (default: 1)
  type RUN_TYPE      Execution mode: JIT | AOT | INTERPRET (default: JIT)
```

**Examples:**
```bash
# Run program once with JIT
gprobetool run 4 input.bin

# Benchmark with 10000 iterations
gprobetool run 4 input.bin repeat 10000

# Compare execution modes
gprobetool run 4 input.bin repeat 1000 type JIT
gprobetool run 4 input.bin repeat 1000 type AOT
gprobetool run 4 input.bin repeat 1000 type INTERPRET
```

**Output:**
```console
Running eBPF program with id 4 and data in file input.bin
Repeat N: 10000 with run type JIT
Time taken: 1250 ns
Return value: 0
```

**Execution modes:**
- `JIT`: LLVM JIT compilation (fast compilation, good performance)
- `AOT`: Pre-compiled native code (best performance, requires prior compilation)
- `INTERPRET`: Bytecode interpreter (slowest, no compilation overhead)

### remove - Clean Up Shared Memory

Remove gprobe shared memory segments system-wide:

```bash
gprobetool remove
```

**Warning:** This destroys all loaded eBPF programs, maps, and state for all processes using gprobe.

**Use cases:**
- Clean up after crashes
- Reset test environment
- Free system resources

## Common Workflows

### Debugging Workflow

1. **Capture current state:**
```bash
gprobetool export debug_state.json
```

2. **Inspect JSON to find program IDs and understand state:**
```bash
cat debug_state.json | jq '.handlers[] | select(.type=="bpf_prog_handler")'
```

3. **Test specific program:**
```bash
gprobetool run 4 test_input.bin
```

### Performance Analysis Workflow

Compare execution modes for a program:

```bash
# Create test data
echo -n "test data" > input.bin

# Benchmark different modes
echo "=== Interpreter ==="
gprobetool run 4 input.bin repeat 10000 type INTERPRET

echo "=== JIT ==="
gprobetool run 4 input.bin repeat 10000 type JIT

echo "=== AOT (after compilation) ==="
gprobe-aot compile  # Compile first
gprobetool run 4 input.bin repeat 10000 type AOT
```

### Backup and Restore

```bash
# Backup before making changes
gprobetool export backup_$(date +%Y%m%d_%H%M%S).json

# ... make changes ...

# Restore if needed
gprobetool remove
gprobetool import backup_20250930_120000.json
```

### Cross-System Testing

Export on development machine, import on test machine:

```bash
# On dev machine
gprobetool export production_config.json
scp production_config.json test-server:~/

# On test machine
gprobetool import production_config.json
```

## JSON Format

The exported JSON contains an array of handlers with this structure:

```json
{
  "handlers": [
    {
      "fd": 3,
      "type": "bpf_map_handler",
      "name": ".rodata.str1.1",
      "attr": {
        "map_type": 2,
        "key_size": 4,
        "value_size": 21,
        "max_entries": 1,
        "flags": 128
      }
    },
    {
      "fd": 4,
      "type": "bpf_prog_handler",
      "name": "do_uprobe_trace",
      "attr": {
        "type": 0,
        "cnt": 16,
        "insns": "<hex-encoded-bytecode>",
        "attach_fds": [5]
      }
    },
    {
      "fd": 5,
      "type": "bpf_perf_event_handler",
      "attr": {
        "type": 6,
        "pid": -1,
        "_module_name": "example/minimal/victim",
        "offset": 4457
      }
    }
  ]
}
```

### Handler Types

- **bpf_map_handler**: eBPF maps (hash, array, ringbuf, etc.)
- **bpf_prog_handler**: eBPF programs with bytecode
- **bpf_perf_event_handler**: Uprobe/kprobe/tracepoint attachments
- **bpf_link_handler**: BPF links connecting programs to hooks

## Environment Variables

- `SPDLOG_LEVEL`: Set logging level (trace, debug, info, warn, error, critical)
  ```bash
  SPDLOG_LEVEL=debug gprobetool import state.json
  ```

## Troubleshooting

**Q: "Global shm not found" error**
A: No gprobe processes are running. Start a process with gprobe first:
```bash
LD_PRELOAD=~/.gprobe/libgprobe-syscall-server.so your_program
```

**Q: "Invalid id not exist" when running**
A: Use `export` to see available program IDs. The ID may have been destroyed or never created.

**Q: "AOT instructions not found" error**
A: The program hasn't been AOT-compiled yet. Run `gprobe-aot compile` first.

**Q: JSON import fails**
A: Ensure the JSON format matches the expected schema. Use `export` to see correct format.

## Performance Notes

- **Export**: Fast, reads shared memory without copying large data
- **Import**: Creates all objects in shared memory, may take time for large programs
- **Run**: Performance depends on execution mode:
  - INTERPRET: ~100-500ns per iteration overhead
  - JIT: ~10-50ns per iteration overhead (first run includes compilation)
  - AOT: ~5-20ns per iteration overhead (pre-compiled)

## Integration with gprobe

`gprobetool` works with the gprobe runtime's shared memory:

```bash
# Terminal 1: Start target with gprobe
LD_PRELOAD=~/.gprobe/libgprobe-syscall-server.so ./my_app

# Terminal 2: Inspect state
gprobetool export current_state.json

# Terminal 3: Run benchmarks
gprobetool run 4 test_data.bin repeat 100000 type JIT
```

## See Also

- [gprobe-aot](https://github.com/Storage-and-OS-for-AI/gprobe/tree/master/tools/aot) - AOT compiler for eBPF programs
- [gprobe documentation](https://github.com/Storage-and-OS-for-AI/gprobe) - Main project documentation
- [Shared memory architecture](https://github.com/Storage-and-OS-for-AI/gprobe/blob/master/runtime/include/gprobe_shm.hpp) - Implementation details
