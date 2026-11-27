# Create a target that builds the ebpf program
add_ebpf_program_target(gprobe_daemon_ebpf_target ${CMAKE_CURRENT_SOURCE_DIR}/kernel/bpf_tracer.bpf.c ${CMAKE_CURRENT_BINARY_DIR}/bpf_tracer.bpf.o)

# Create a target that generated the bpf skeleton
add_bpf_skel_generating_target(gprobe_daemon_ebpf_skel ${CMAKE_CURRENT_BINARY_DIR}/bpf_tracer.bpf.o ${CMAKE_CURRENT_BINARY_DIR}/bpf_tracer.skel.h)

add_dependencies(gprobe_daemon_ebpf_skel gprobe_daemon_ebpf_target)

add_executable(embedfile ${CMAKE_CURRENT_SOURCE_DIR}/assets/embedfile.c)

set(PLACEHOLDER_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/assets/placeholder)
set(PLACEHOLDER_OUTPUT placeholder.c)

add_custom_command(
    OUTPUT placeholder.c
    COMMAND embedfile placeholder ${PLACEHOLDER_INPUT} ${PLACEHOLDER_OUTPUT}
    DEPENDS ${PLACEHOLDER_INPUT})

add_library(libgprobe_daemon STATIC
    user/bpf_tracer.cpp
    user/handle_bpf_event.cpp
    user/gprobe_driver.cpp
    ${PLACEHOLDER_OUTPUT}
)

add_executable(gprobe_daemon
    user/main.cpp
)

add_dependencies(libgprobe_daemon
    gprobe_daemon_ebpf_skel
    libbpf
    spdlog::spdlog
    runtime
)

target_include_directories(libgprobe_daemon PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBBPF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../vm/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/libbpf/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/libbpf/include/uapi
)

target_link_libraries(libgprobe_daemon PRIVATE
    ${LIBBPF_LIBRARIES}
    elf
    z
    spdlog::spdlog
    runtime
    PUBLIC
    rt
)

if(${GPROBE_ENABLE_CUDA_ATTACH})
    include(../cmake/cuda.cmake)
    find_cuda()
    target_link_directories(libgprobe_daemon PUBLIC ${CUDA_LIBRARY_PATH})
    target_link_libraries(libgprobe_daemon PRIVATE ${CUDA_LIBS})
endif()

set_property(TARGET libgprobe_daemon PROPERTY CXX_STANDARD 20)

add_dependencies(gprobe_daemon libgprobe_daemon)
target_link_libraries(gprobe_daemon PRIVATE libgprobe_daemon spdlog::spdlog)

install(TARGETS gprobe_daemon CONFIGURATIONS Release Debug RelWithDebInfo DESTINATION ~/.gprobe)

if(GPROBE_ENABLE_UNIT_TESTING)
    add_subdirectory(test)
endif()

if(${TEST_LCOV})
    target_compile_options(gprobe_daemon PUBLIC -fprofile-arcs -ftest-coverage -fprofile-update=atomic)
    target_link_options(gprobe_daemon PUBLIC -fprofile-arcs)
endif()
