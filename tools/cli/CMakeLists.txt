add_executable(
    gprobe-cli-cpp
    main.cpp
)

set_target_properties(gprobe-cli-cpp PROPERTIES OUTPUT_NAME "gprobe")

target_include_directories(gprobe-cli-cpp PRIVATE ${FRIDA_CORE_INSTALL_DIR} ${SPDLOG_INCLUDE} ${argparse_INCLUDE} ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime/include ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime/src ${CMAKE_CURRENT_SOURCE_DIR}/../../vm/vm-core/include)
target_link_libraries(gprobe-cli-cpp PRIVATE spdlog::spdlog ${FRIDA_CORE_INSTALL_DIR}/libfrida-core.a argparse spdlog::spdlog gprobe_vm_compat runtime)
# Link the VM compat static libs exactly once via runtime to avoid duplicate symbols
if(${GPROBE_UBPF_JIT})
  add_dependencies(gprobe-cli-cpp gprobe_ubpf_vm)
  target_link_options(gprobe-cli-cpp PUBLIC "-Wl,--whole-archive" "$<TARGET_FILE:gprobe_ubpf_vm>" "-Wl,--no-whole-archive")
  target_link_libraries(gprobe-cli-cpp PUBLIC gprobe_ubpf_vm)
endif()
if(${GPROBE_LLVM_JIT})
  add_dependencies(gprobe-cli-cpp gprobe_llvm_vm llvmbpf_vm)
  target_link_options(gprobe-cli-cpp PUBLIC "-Wl,--whole-archive" "$<TARGET_FILE:gprobe_llvm_vm>" "-Wl,--no-whole-archive")
  target_link_libraries(gprobe-cli-cpp PUBLIC gprobe_llvm_vm)
endif()
set_property(TARGET gprobe-cli-cpp PROPERTY CXX_STANDARD 20)

target_compile_definitions(gprobe-cli-cpp PRIVATE _GNU_SOURCE)

add_dependencies(gprobe-cli-cpp spdlog::spdlog FridaCore argparse spdlog runtime gprobe_vm gprobe_vm_compat)

install(TARGETS gprobe-cli-cpp CONFIGURATIONS Release Debug RelWithDebInfo DESTINATION ~/.gprobe)
