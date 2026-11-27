cmake_minimum_required(VERSION 3.15)

add_library(gprobe_vm STATIC ./src/ebpf-vm.cpp)

target_include_directories(gprobe_vm PRIVATE ./include INTERFACE ./include)


if(${GPROBE_LLVM_JIT})
  add_dependencies(gprobe_vm gprobe_vm_compat spdlog "gprobe_llvm_vm")
  target_link_libraries(gprobe_vm PUBLIC gprobe_vm_compat spdlog "gprobe_llvm_vm")
endif()

if(${GPROBE_UBPF_JIT})
  add_dependencies(gprobe_vm gprobe_vm_compat spdlog "gprobe_ubpf_vm")
  target_link_libraries(gprobe_vm PUBLIC gprobe_vm_compat spdlog "gprobe_ubpf_vm")
endif()

