cmake_minimum_required(VERSION 3.16)
#
# Project details
#
project(
  "vm-bpf"
  VERSION 0.9.0
  LANGUAGES C CXX
)

if(NOT DEFINED GPROBE_LLVM_JIT)
  set(GPROBE_LLVM_JIT ON CACHE BOOL "Use LLVM as jit backend.")
endif()

if(NOT DEFINED GPROBE_UBPF_JIT)
  set(GPROBE_UBPF_JIT ON CACHE BOOL "Use uBPF as jit backend.")
endif()


if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

if(NOT DEFINED SPDLOG_INCLUDE)
  message(STATUS "Adding spdlog seperately..")
  # spdlog
  add_subdirectory(../third_party/spdlog ${CMAKE_CURRENT_BINARY_DIR}/spdlog)
  set(SPDLOG_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/spdlog/include)
endif()

if(${GPROBE_BUILD_STANDALONE_VM})
  include(../cmake/libbpf.cmake)
  add_subdirectory(../third_party/argparse ${CMAKE_CURRENT_BINARY_DIR}/argparse)
endif()

if(${GPROBE_LLVM_JIT})
  set(GPROBE_BPF_RUNTIME_NAME "gprobe_llvm_vm")
endif()

if(${GPROBE_UBPF_JIT})
  set(GPROBE_BPF_RUNTIME_NAME "gprobe_ubpf_vm")
endif()

if(NOT GPROBE_BPF_RUNTIME_NAME)
  message(WARNING "No built-in VMs has been enabled.")
endif()

add_subdirectory(compat)
add_subdirectory(vm-core)

#
# Unit testing setup
#
set(test_sources
  src/test.c
  src/test_jit.c
  src/test_vm.c
  src/test_core_minimal_ffi.c
)

if(GPROBE_ENABLE_UNIT_TESTING)
  enable_testing()
  message(STATUS "Build unit tests for the project. Tests should always be found in the test folder\n")
  if(GPROBE_UBPF_JIT AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Retain the uBPF factory registration from the static library.
    add_executable(gprobe_ubpf_lifetime_test
      test/ubpf_lifetime.cpp
      $<TARGET_OBJECTS:gprobe_ubpf_vm_obj>)
    target_link_libraries(gprobe_ubpf_lifetime_test PRIVATE gprobe_vm)
    target_include_directories(gprobe_ubpf_lifetime_test PRIVATE
      compat/ubpf-vm)
    target_compile_features(gprobe_ubpf_lifetime_test PRIVATE cxx_std_17)
    target_link_options(gprobe_ubpf_lifetime_test PRIVATE
      -Wl,--wrap=ubpf_create -Wl,--wrap=ubpf_destroy)
    add_test(NAME gprobe_ubpf_lifetime COMMAND gprobe_ubpf_lifetime_test)
  endif()
endif()
