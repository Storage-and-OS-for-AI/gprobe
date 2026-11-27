add_executable(
    gprobe-aot-cli
    main.cpp
)

set_target_properties(gprobe-aot-cli PROPERTIES OUTPUT_NAME "gprobe-aot")

target_include_directories(gprobe-aot-cli PRIVATE 
    ${SPDLOG_INCLUDE} 
    ${argparse_INCLUDE} 
    ${CMAKE_CURRENT_SOURCE_DIR}/../../vm/compat/include
    ../../runtime/include/
    ../../runtime/src/
    ${LIBBPF_INCLUDE_DIRS}
    ${LLVM_INCLUDE_DIRS}
)
if(${GPROBE_ENABLE_CUDA_ATTACH})
    include(../../cmake/cuda.cmake)
    find_cuda()
    target_link_directories(gprobe-aot-cli PRIVATE ${CUDA_LIBRARY_PATH})
    # Use --whole-archive to include all symbols from gprobe_llvm_vm
    # This ensures the constructor function register_llvm_vm_factory() is linked
    target_link_options(gprobe-aot-cli PRIVATE 
        "-Wl,--whole-archive" 
        "$<TARGET_FILE:gprobe_llvm_vm>" 
        "-Wl,--no-whole-archive")
    target_link_libraries(gprobe-aot-cli PRIVATE -L/usr/lib/llvm-20/lib/ spdlog::spdlog argparse gprobe_vm_compat gprobe_llvm_vm runtime ${LIBBPF_LIBRARIES} elf z ${LLVM_LIBRARIES} ${llvm_libs} ${CUDA_LIBS} gprobe_nv_attach_impl)
else()
    # Use --whole-archive to include all symbols from gprobe_llvm_vm
    # This ensures the constructor function register_llvm_vm_factory() is linked
    target_link_options(gprobe-aot-cli PRIVATE 
        "-Wl,--whole-archive" 
        "$<TARGET_FILE:gprobe_llvm_vm>" 
        "-Wl,--no-whole-archive")
    target_link_libraries(gprobe-aot-cli PRIVATE -L/usr/lib/llvm-20/lib/ spdlog::spdlog argparse gprobe_vm_compat gprobe_llvm_vm runtime ${LIBBPF_LIBRARIES} elf z ${LLVM_LIBRARIES} ${llvm_libs})
endif()
set_property(TARGET gprobe-aot-cli PROPERTY CXX_STANDARD 20)

target_compile_definitions(gprobe-aot-cli PRIVATE _GNU_SOURCE)

add_dependencies(gprobe-aot-cli spdlog::spdlog argparse gprobe_vm_compat gprobe_llvm_vm libbpf)

install(TARGETS gprobe-aot-cli CONFIGURATIONS Release Debug RelWithDebInfo DESTINATION ~/.gprobe)
