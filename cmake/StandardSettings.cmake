#
# Project settings
#

option(GPROBE_BUILD_EXECUTABLE "Build the project as an executable, rather than a library." OFF)

#
# library options
#
option(GPROBE_LLVM_JIT "Use LLVM as jit backend." ON)
option(GPROBE_UBPF_JIT "Use uBPF as jit backend." ON)

#
# Compiler options
#

option(GPROBE_WARNINGS_AS_ERRORS "Treat compiler warnings as errors." OFF)

#
#
# CUDA options
#

option(GPROBE_CUDA_ROOT "Root for CUDA installation" "")
option(GPROBE_ENABLE_CUDA_ATTACH "Whether to enable CUDA attach" OFF)

#
# ROCm options
#
option(GPROBE_ROCM_ROOT "Root for ROCm installation" "")
option(GPROBE_ENABLE_ROCM_ATTACH "Whether to enable ROCm/HIP attach" OFF)

#
# MACA options
#
option(GPROBE_MACA_ROOT "Root for MACA (MetaX) installation" "")
option(GPROBE_ENABLE_MACA_ATTACH "Whether to enable MACA (MetaX) attach" OFF)

#
# Unit testing
#
# Currently supporting: GoogleTest, Catch2.

option(GPROBE_ENABLE_UNIT_TESTING "Enable unit tests for the projects (from the `test` subfolder)." OFF)

option(GPROBE_USE_CATCH2 "Use the Catch2 project for creating unit tests." OFF)

#
# Miscelanious options
#

# Generate compile_commands.json for clang based tools
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(GPROBE_VERBOSE_OUTPUT "Enable verbose output, allowing for a better understanding of each step taken." ON)

# Export all symbols when building a shared library
if(BUILD_SHARED_LIBS)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)
  set(CMAKE_CXX_VISIBILITY_PRESET hidden)
  set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
endif()

option(GPROBE_ENABLE_LTO "Enable Interprocedural Optimization, aka Link Time Optimization (LTO)." OFF)
if(GPROBE_ENABLE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT result OUTPUT output)
  if(result)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
  else()
    message(SEND_ERROR "IPO is not supported: ${output}.")
  endif()
endif()

option(GPROBE_ENABLE_CCACHE "Enable the usage of Ccache, in order to speed up rebuild times." OFF)
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif()

option(GPROBE_ENABLE_ASAN "Enable Address Sanitize to detect memory error." OFF)
if(GPROBE_ENABLE_ASAN)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^riscv")
    set(GPROBE_ENABLE_TRAP_UPROBE ON CACHE BOOL "Build the trap (breakpoint + SIGTRAP) uprobe backend" FORCE)
    set(GPROBE_ENABLE_FRIDA OFF CACHE BOOL "Build the frida-gum based uprobe backend" FORCE)
else()
    set(GPROBE_ENABLE_TRAP_UPROBE OFF CACHE BOOL "Build the trap (breakpoint + SIGTRAP) uprobe backend" FORCE)
    set(GPROBE_ENABLE_FRIDA ON CACHE BOOL "Build the frida-gum based uprobe backend" FORCE)
endif()

option(GPROBE_ENABLE_MPK "Enable Memory Protection Keys for the share memory." OFF)
if(GPROBE_ENABLE_MPK)
    add_definitions(-DGPROBE_ENABLE_MPK)
endif()

option(GPROBE_ENABLE_IOURING_EXT "Enable iouring helpers extensions." OFF)
if(GPROBE_ENABLE_IOURING_EXT)
    add_definitions(-DGPROBE_ENABLE_IOURING_EXT)
endif()

# whether to enable eBPF verifier in userspace
option(ENABLE_EBPF_VERIFIER "Whether to enable ebpf verifier" OFF)

# whether to build with gprobe daemon
option(BUILD_GPROBE_DAEMON "Whether to build the gprobe daemon" ON)

# whether to build with shared bpf_map
option(GPROBE_BUILD_KERNEL_BPF "Whether to build with bpf share maps" ON)

# whether to build single static library
option(GPROBE_BUILD_STATIC_LIB "Whether to build a single static library for different archive files" OFF)

# whether to build gprobe with libbpf and other linux headers
option(GPROBE_BUILD_WITH_LIBBPF "Whether to build with libbpf and other linux headers" ON)

# whether to enable probe read check
option(ENABLE_PROBE_READ_CHECK "Whether to enable probe read check" ON)
# whether to enable probe write check
option(ENABLE_PROBE_WRITE_CHECK "Whether to enable probe write check" ON)
