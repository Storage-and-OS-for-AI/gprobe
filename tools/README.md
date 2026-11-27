# Tools

This directory contains additional tools for gprobe to improve the user experience, providing high-level interfaces for eBPF program management, compilation, and runtime control.

## Installation

Install all CLI tools and libraries:

```bash
make install
export PATH=$PATH:~/.gprobe
```

After installation, the following tools will be available in `~/.gprobe/`:

- `gprobe` - Main CLI interface for running and managing eBPF programs
- `gprobetool` - Tool for inspecting and managing shared memory state
- `gprobe-aot` - AOT (Ahead-of-Time) compilation tool for eBPF to native code

## Tools Overview

### 1. gprobe CLI (`gprobe`)

**Purpose**: High-level interface for injecting gprobe runtime into target processes using `LD_PRELOAD`. This is the primary user-facing tool for running eBPF programs in userspace.

**Usage**:
```bash
gprobe [OPTIONS] COMMAND
```

**Commands**:

#### `load` - Start application with syscall server
Injects the gprobe syscall server into the target application to intercept eBPF-related system calls.

```bash
gprobe load <COMMAND> [ARGS...]
```

**Example**:
```bash
# Run application with eBPF syscall interception
gprobe load ./my_ebpf_program
```

#### `start` - Start application with gprobe agent
Injects the gprobe agent into the target application for eBPF program execution.

```bash
gprobe start [OPTIONS] <COMMAND> [ARGS...]
```

**Options**:
- `-s, --enable-syscall-trace`: Enable syscall tracing functionality

**Examples**:
```bash
# Basic agent injection
gprobe start ./target_application

# With syscall tracing enabled
gprobe start -s ./target_application
```

#### `attach` - Inject gprobe agent to running process
Dynamically attaches the gprobe agent to an already running process using Frida injection.

```bash
gprobe attach [OPTIONS] <PID>
```

**Options**:
- `-s, --enable-syscall-trace`: Enable syscall tracing functionality

**Examples**:
```bash
# Attach to process with PID 1234
gprobe attach 1234

# Attach with syscall tracing
gprobe attach -s 1234
```

#### `detach` - Detach all attached agents
Sends SIGUSR1 signal to all processes with attached gprobe agents to trigger detachment.

```bash
gprobe detach
```

**Global Options**:
- `-i, --install-location <PATH>`: Specify gprobe installation directory (default: `~/.gprobe`)
- `-d, --dry-run`: Run without committing any modifications

### 2. gprobe Tool (`gprobetool`)

**Purpose**: Inspect and manage the shared memory state containing eBPF objects (programs, maps, links). Provides serialization capabilities for persistent storage and transfer.

**Usage**:
```bash
gprobetool COMMAND [OPTIONS]
```

**Commands**:

#### `export` - Export shared memory to JSON
Serializes the current gprobe shared memory state to a JSON file for backup or analysis.

```bash
gprobetool export <filename.json>
```

**Example**:
```bash
gprobetool export my_ebpf_state.json
```

#### `import` - Import JSON into shared memory
Loads eBPF objects from a JSON file into the gprobe shared memory system.

```bash
gprobetool import <filename.json>
```

**Example**:
```bash
gprobetool import my_ebpf_state.json
```

#### `load` - Load JSON with specific fd mapping
Loads eBPF objects from JSON with a specific file descriptor mapping.

```bash
gprobetool load <fd> <JSON>
```

**Parameters**:
- `<fd>`: File descriptor to map
- `<JSON>`: JSON string containing eBPF objects

**Note**: This command is primarily for internal use when mapping specific file descriptors.

#### `remove` - Remove global shared memory
Completely removes the gprobe shared memory system wide.

```bash
gprobetool remove
```

#### `run` - Execute eBPF program from shared memory
Runs an eBPF program stored in shared memory with provided input data.

```bash
gprobetool run <id> <data_file> [repeat <N>] [type <RUN_TYPE>]
```

**Parameters**:
- `<id>`: Program ID in shared memory
- `<data_file>`: Binary file containing input data for the program
- `repeat <N>`: Number of times to execute (default: 1)
- `type <RUN_TYPE>`: Execution mode (JIT, AOT, INTERPRET)

**Run Types**:
- `JIT`: Just-In-Time compilation (default)
- `AOT`: Ahead-of-Time compiled code
- `INTERPRET`: Interpreted execution

**Examples**:
```bash
# Run program ID 0 with input data
gprobetool run 0 input.bin

# Run with 1000 iterations for benchmarking
gprobetool run 0 input.bin repeat 1000

# Run AOT-compiled version
gprobetool run 0 input.bin type AOT

# Combined options
gprobetool run 0 input.bin repeat 100 type JIT
```

### 3. gprobe AOT Tool (`gprobe-aot`)

**Purpose**: Ahead-of-Time (AOT) compilation tool that compiles eBPF bytecode to native machine code for maximum performance. Supports both ELF-based compilation and shared memory compilation.

**Usage**:
```bash
gprobe-aot COMMAND [OPTIONS]
```

**Commands**:

#### `build` - Compile eBPF ELF to native ELF
Compiles eBPF programs from an ELF file to native machine code.

```bash
gprobe-aot build [OPTIONS] <EBPF_ELF>
```

**Options**:
- `-o, --output <DIR>`: Output directory (default: current directory)
- `-e, --emit_llvm`: Emit LLVM IR files alongside native code

**Example**:
```bash
# Compile eBPF ELF to native code
gprobe-aot build my_program.bpf.o -o ./output/

# Emit LLVM IR for analysis
gprobe-aot build my_program.bpf.o -e
```

#### `compile` - Compile programs from shared memory
Compiles eBPF programs currently loaded in gprobe shared memory to native code.

```bash
gprobe-aot compile [OPTIONS]
```

**Options**:
- `-o, --output <DIR>`: Output directory (default: current directory)
- `-e, --emit_llvm`: Emit LLVM IR files alongside native code

**Example**:
```bash
# Compile all programs in shared memory
gprobe-aot compile -o ./compiled/

# With LLVM IR emission
gprobe-aot compile -e
```

#### `load` - Load AOT object into shared memory
Loads a pre-compiled native ELF file into shared memory for a specific program ID.

```bash
gprobe-aot load <ELF_PATH> <PROGRAM_ID>
```

**Example**:
```bash
# Load compiled object for program ID 0
gprobe-aot load do_count.o 0
```

#### `run` - Execute native eBPF program
Directly executes a native eBPF program with optional input data.

```bash
gprobe-aot run <ELF_PATH> [MEMORY_FILE]
```

**Parameters**:
- `<ELF_PATH>`: Path to native ELF file
- `[MEMORY_FILE]`: Optional binary file with input memory

**Example**:
```bash
# Run native program
gprobe-aot run do_count.o

# Run with input data
gprobe-aot run do_count.o input_data.bin
```

### AOT Compilation Workflow

The AOT tool supports two main workflows:

#### 1. Direct ELF Compilation
```bash
# Compile eBPF ELF to native
gprobe-aot build program.bpf.o -o output/

# Link with your application
clang -O2 main.c output/program.o -o final_app
```

#### 2. Shared Memory Compilation
```bash
# Load eBPF program (using syscall server)
LD_PRELOAD=libgprobe-syscall-server.so ./ebpf_loader

# Compile loaded programs
gprobe-aot compile -o output/

# Load back into shared memory
gprobe-aot load output/program.o 0
```

## Development and Testing Tools

### ARM64 Build Testing
Test gprobe compilation on ARM64 architecture using Docker:

```bash
./tools/test_arm_build.sh
```

This script:
1. Builds Docker image for ARM64
2. Tests release build compilation
3. Verifies example programs build correctly

### Docker Support
Multiple Dockerfiles for different environments:

- `Dockerfile.ubuntu`: Ubuntu 22.04 based development environment
- `Dockerfile.fedora`: Fedora based environment  
- `Dockerfile.arm`: ARM64 cross-compilation environment

## Integration Examples

### Complete Workflow Example

1. **Load eBPF program with syscall interception**:
   ```bash
   gprobe load ./my_ebpf_app
   ```

2. **Export state for analysis**:
   ```bash
   gprobetool export program_state.json
   ```

3. **Compile to native code**:
   ```bash
   gprobe-aot compile -o native_output/
   ```

4. **Benchmark different execution modes**:
   ```bash
   gprobetool run 0 test_data.bin repeat 1000 type INTERPRET
   gprobetool run 0 test_data.bin repeat 1000 type JIT
   gprobetool run 0 test_data.bin repeat 1000 type AOT
   ```

### Performance Testing
```bash
# Load and run with performance measurement
gprobe start ./target_app
gprobetool run 0 input.bin repeat 10000 type JIT
```

## Environment Variables

### Common Variables
- `SPDLOG_LEVEL`: Control logging level (trace, debug, info, warn, error, critical)
  ```bash
  SPDLOG_LEVEL=debug gprobetool import program.json
  ```

### gprobe CLI Variables
- `HOME`: Used to determine default installation location (`~/.gprobe`)
- `PATH`: Should include gprobe installation directory after installation
- `LD_PRELOAD`: Automatically set by the tool when injecting libraries
- `AGENT_SO`: Used internally to specify the agent library path

### Platform-Specific Libraries
The tools automatically use the correct library names based on platform:
- **Linux**: `.so` files (e.g., `libgprobe-agent.so`)
- **macOS**: `.dylib` files (e.g., `libgprobe-agent.dylib`)
