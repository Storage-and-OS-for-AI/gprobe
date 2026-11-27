# add eBPF program target and controller executable target
add_executable(attach_impl_example_controller
    ./controller.cpp
)
add_ebpf_program_target(
    attach_impl_example_ebpf_program
    ${CMAKE_CURRENT_SOURCE_DIR}/request_filter.bpf.c
    ${CMAKE_CURRENT_BINARY_DIR}/request_filter.bpf.o
)
target_compile_definitions(attach_impl_example_controller PRIVATE EBPF_PROGRAM_PATH=${CMAKE_CURRENT_BINARY_DIR}/request_filter.bpf.o)

add_dependencies(attach_impl_example_controller runtime spdlog::spdlog gprobe-object attach_impl_example_ebpf_program)

add_dependencies(attach_impl_example_controller gprobe_llvm_vm)

target_link_libraries(attach_impl_example_controller PRIVATE runtime spdlog::spdlog gprobe-object gprobe_llvm_vm)

# Keep constructor-based VM factory registration (llvm) from being dropped by the linker
if(UNIX AND NOT APPLE)
  target_link_options(attach_impl_example_controller PUBLIC "-Wl,--whole-archive" "$<TARGET_FILE:gprobe_llvm_vm>" "-Wl,--no-whole-archive")
endif()
target_include_directories(attach_impl_example_controller PRIVATE ${GPROBE_RUNTIME_INCLUDE} ${SPDLOG_INCLUDE} ${GPROBE_OBJECT_INCLUDE_DIRS})
