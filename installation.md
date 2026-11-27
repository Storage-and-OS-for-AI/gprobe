# Installation and Test

## Table of Contents

<!-- TOC -->

- [Building and Test](#building-and-test)
  - [Table of Contents](#table-of-contents)
  - [Use docker image](#use-docker-image)
  - [Install Dependencies](#install-dependencies)
    - [Build and install all things](#build-and-install-all-things)
  - [Detailed things about building](#detailed-things-about-building)
    - [build options](#build-options)
    - [Build and install the complete runtime in release mode(With ubpf jit)](#build-and-install-the-complete-runtime-in-release-modewith-ubpf-jit)
    - [Build and install the complete runtime in debug mode(With ubpf jit)](#build-and-install-the-complete-runtime-in-debug-modewith-ubpf-jit)
    - [Build and install the complete runtime in release mode(With llvm jit)](#build-and-install-the-complete-runtime-in-release-modewith-llvm-jit)
    - [Compile with LTO enabled](#compile-with-lto-enabled)
    - [Compile with userspace verifier](#compile-with-userspace-verifier)
    - [Compile with libbpf disabled](#compile-with-libbpf-disabled)
    - [Testing targets](#testing-targets)
  - [Compile only the vm (No runtime, No uprobe)](#compile-only-the-vm-no-runtime-no-uprobe)
  - [More compile options](#more-compile-options)

<!-- /TOC -->

## Use docker image

We provide a docker image for building and testing gprobe.

```bash
# run the container
docker run -it --rm --name test_gprobe -v "$(pwd)":/workdir -w /workdir ghcr.io/Storage-and-OS-for-AI/gprobe:latest /bin/bash
# start another shell in the container (If needed)
docker exec -it test_gprobe /bin/bash
```

Or build the docker from dockerfile:

```bash
git submodule update --init --recursive
docker build .
```

## Install Dependencies

Install the required packages:

```bash
sudo apt-get update && sudo apt-get install \
        libelf1 libelf-dev zlib1g-dev make cmake git libboost-all-dev \
        binutils-dev libyaml-cpp-dev ca-certificates clang llvm pkg-config llvm-dev
git submodule update --init --recursive
```

We've tested on Ubuntu 23.04. The recommended `gcc` >= 12.0.0 `clang` >= 16.0.0. It's recommanded to use `libboost1.74-all-dev`.

On Ubuntu 20.04, you may need to manually switch to gcc-12.

### Build and install all things

Install all things that could be installed to `~/.gprobe`, includes:

- `gprobe`: A cli tool used for injecting agent & server to userspace programs
- `gprobe-vm`: A cli tool used for compiling eBPF programs into native programs, or run the compiled program
- `gprobetool`: A cli tool used to manage things stored in shared memory, such as the data of maps or programs
- `gprobe_daemon`: An executable used for implementing the similar thing like syscall server, but don't need to be injected to the userspace program
- `libgprobe-agent.so`, `libgprobe-agent-transformer.so`: Libraries needed by gprobe agent
- `libgprobe-syscall-server.so`: Library needed by gprobe syscall server

Build with makefile:

```bash
make release JOBS=$(nproc) # Build and install the runtime
export PATH=$PATH:~/.gprobe
```

Or you can also build with `cmake`(The Makefile is a wrapper of cmake commands):

```bash
cmake -Bbuild  -DCMAKE_BUILD_TYPE:STRING=Release \
           -DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO
cmake --build build --config Release --target install
export PATH=$PATH:~/.gprobe
```

Then you can run cli:

```console
$ gprobe
Usage: gprobe [OPTIONS] <COMMAND>
...
```

See the [Makefile](https://github.com/Storage-and-OS-for-AI/gprobe/blob/master/Makefile) for some common commands.

## Detailed things about building

We use cmake as build system.

### build options

You may be interested in the following cmake options:

- `CMAKE_BUILD_TYPE`: Specify the build type. It could be `Debug`, `Release`, `MinSizeRel` or `RelWithDebInfo`. If you are not going to debug gprobe, you just need to set it to `Release`. Default to `Debug`.
- `GPROBE_ENABLE_UNIT_TESTING`: Whether to build unit test targets. See `Testing targets` for details. Default to `NO`.
- `GPROBE_ENABLE_LTO`: Whether to enable Link Time Optimization. Enabling this may increase the compile time, but it may lead to a better performance. Default to `No`.
- `GPROBE_ENABLE_CCACHE`: Enable the usage of Ccache to speed up rebuild times. Default to `OFF`.
- `GPROBE_ENABLE_ASAN`: Enable Address Sanitizer to detect memory errors. Default to `OFF`.
- `ENABLE_EBPF_VERIFIER`: Whether to enable userspace eBPF verifier. Default to `OFF`.
- `GPROBE_LLVM_JIT`: Whether to use LLVM JIT as the ebpf runtime. Requires LLVM >= 15. It's recommended to enable this, since the ubpf intepreter is no longer maintained. Default to `ON`.
- `GPROBE_UBPF_JIT`: Whether to use uBPF JIT backend. Default to `ON`.
- `LLVM_DIR`: Specify the installing directory of LLVM. CMake may not discover the LLVM installation by default. Set this option to the directory that contains `LLVMConfig.cmake`, such as `/usr/lib/llvm-15/cmake` on Ubuntu
- `BUILD_GPROBE_DAEMON`: Build with the daemon for load the eBPF program into hkernel and se kernel verifier. Default to `ON`.
- `GPROBE_BUILD_WITH_LIBBPF`: Build gprobe with libbpf. When disabled, it can only be run in userspace but can be easily ported to other platforms, e.g. macOS. Default to `ON`.
- `GPROBE_BUILD_KERNEL_BPF`: Whether to build with bpf share maps. Default to `ON`.
- `GPROBE_BUILD_STATIC_LIB`: Build gprobe runtime into a whole static libraries. It can be easily linked into other programs. Default to `OFF`.
- `GPROBE_ENABLE_MPK`: Enable Memory Protection Keys for the shared memory. Default to `OFF`.
- `GPROBE_ENABLE_IOURING_EXT`: Enable iouring helpers extensions. Default to `OFF`.
- `ENABLE_PROBE_WRITE_CHECK`: Enable the probe write check. It will check the bpf_probe_write_user operation and report the error if the probe write address is invalid. Default to `ON`.
- `ENABLE_PROBE_READ_CHECK`: Enable the probe read check. It will check the bpf_probe_write operation and report the error if the probe read address is invalid. Default to `ON`.
- `GPROBE_ENABLE_CUDA_ATTACH`: Enable CUDA/GPU attach support. Requires `GPROBE_CUDA_ROOT` to be set to the CUDA installation directory (e.g., `/usr/local/cuda-12.8`). Default to `OFF`.
- `GPROBE_CUDA_ROOT`: Specify the root directory of CUDA installation. Required when `GPROBE_ENABLE_CUDA_ATTACH=1`.
- `GPROBE_WARNINGS_AS_ERRORS`: Treat compiler warnings as errors. Default to `OFF`.
- `GPROBE_VERBOSE_OUTPUT`: Enable verbose output, allowing for a better understanding of each step taken. Default to `ON`.

Please see <https://github.com/Storage-and-OS-for-AI/gprobe/blob/master/cmake/StandardSettings.cmake> forall the build options.

### Build and install the complete runtime in release mode(With ubpf jit)

```bash
cmake -Bbuild -DCMAKE_BUILD_TYPE=Release -DGPROBE_ENABLE_LTO=NO
cmake --build build --config Release --target install
```

### Build and install the complete runtime in debug mode(With ubpf jit)

```bash
cmake -Bbuild -DCMAKE_BUILD_TYPE=Debug -DGPROBE_ENABLE_LTO=NO
cmake --build build --config Debug --target install
```

### Build and install the complete runtime in release mode(With llvm jit)

```bash
cmake -Bbuild -DCMAKE_BUILD_TYPE=Release -DGPROBE_ENABLE_LTO=NO -DGPROBE_LLVM_JIT=YES
cmake --build build --config RelWithDebInfo --target install
```

### Compile with LTO enabled

Just set `GPROBE_ENABLE_LTO` to `YES`

For example, build  the package, with llvm-jit and LTO enabled:

```sh
cmake -Bbuild -DCMAKE_BUILD_TYPE=Release -DGPROBE_ENABLE_LTO=YES -DGPROBE_LLVM_JIT=YES
cmake --build build --config RelWithDebInfo --target install
```

### Compile with userspace verifier

Note that we are using <https://github.com/vbpf/ebpf-verifier> as userspace verifier. It's not perfect, and may not support some features (such as ringbuf)

```sh
cmake -DGPROBE_LLVM_JIT=NO -DENABLE_EBPF_VERIFIER=YES -DCMAKE_BUILD_TYPE=Release -B build
cmake --build build --config Release --target install
```

### Compile with libbpf disabled

This flag can be used to compile `gprobe` on macOS. It will disable all the libbpf related libraries and features that are used in gprobe.

```sh
cmake -Bbuild -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DGPROBE_BUILD_WITH_LIBBPF=OFF -DGPROBE_BUILD_KERNEL_BPF=OFF
cmake --build build --config RelWithDebInfo  --target install -j$(JOBS)
```

### Compile with CUDA/GPU attach support

To enable CUDA attach support, set `GPROBE_ENABLE_CUDA_ATTACH=1` and specify the CUDA installation path:

```sh
# Example with CUDA 12.8
cmake -Bbuild -DCMAKE_BUILD_TYPE=Release -DGPROBE_ENABLE_CUDA_ATTACH=1 -DGPROBE_CUDA_ROOT=/usr/local/cuda-12.8
cmake --build build --config Release --target install
```

Note: Ensure that `GPROBE_CUDA_ROOT` points to your CUDA installation directory (e.g., `/usr/local/cuda-12.8`, `/usr/local/cuda-12.6`, etc.).

### Testing targets

We have some targets for unit testing, they are:

- `gprobe_daemon_tests`
- `gprobe_runtime_tests`
- `llvm_jit_tests`

These targets will only be enabled when `GPROBE_ENABLE_UNIT_TESTING` was set to `YES`.

Build and run them to test, for example:

```sh
cmake -DCMAKE_PREFIX_PATH=/usr/include/llvm -DGPROBE_LLVM_JIT=YES -DGPROBE_ENABLE_UNIT_TESTING=YES -DCMAKE_BUILD_TYPE=Release -B build
cmake --build build --config RelWithDebInfo --target gprobe_runtime_tests
sudo ./build/runtime/unit-test/gprobe_runtime_tests
```

## Compile only the vm (No runtime, No uprobe)

For a lightweight build without the runtime (only vm library and LLVM JIT):

```bash
make build-vm # build the simple vm with a simple jit
make build-llvm # build the vm with llvm jit
```

## More compile options

See <https://github.com/Storage-and-OS-for-AI/gprobe/blob/master/cmake/StandardSettings.cmake> for all cmake build options.

