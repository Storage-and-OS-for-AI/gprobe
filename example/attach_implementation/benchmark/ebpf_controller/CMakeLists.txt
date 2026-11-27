# add eBPF program target and controller executable target
add_executable(nginx_benchmark_ebpf_controller
    ./controller.cpp
)
add_ebpf_program_target(
    nginx_benchmark_ebpf_program
    ${CMAKE_CURRENT_SOURCE_DIR}/request_filter.bpf.c
    ${CMAKE_CURRENT_BINARY_DIR}/request_filter.bpf.o
)
target_compile_definitions(nginx_benchmark_ebpf_controller PRIVATE EBPF_PROGRAM_PATH=${CMAKE_CURRENT_BINARY_DIR}/request_filter.bpf.o)

add_dependencies(nginx_benchmark_ebpf_controller runtime spdlog::spdlog gprobe-object nginx_benchmark_ebpf_program)

target_link_libraries(nginx_benchmark_ebpf_controller PRIVATE runtime spdlog::spdlog gprobe-object)
target_include_directories(nginx_benchmark_ebpf_controller PRIVATE ${GPROBE_RUNTIME_INCLUDE} ${SPDLOG_INCLUDE} ${GPROBE_OBJECT_INCLUDE_DIRS})
