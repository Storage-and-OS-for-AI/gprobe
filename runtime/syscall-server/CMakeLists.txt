project(
    "gprobe-syscall-polyfill"
    VERSION 0.9.0
    LANGUAGES C CXX
)

add_library(gprobe-syscall-server SHARED
    syscall_context.cpp
    syscall_server_main.cpp
    syscall_server_utils.cpp
)

# Force link VM compat libraries so constructor-based factory registration is retained
# Ensure VM compat libraries are linked (once) via the runtime library instead of duplicating at server
if(${GPROBE_UBPF_JIT})
  add_dependencies(gprobe-syscall-server gprobe_ubpf_vm)
  target_link_options(gprobe-syscall-server PUBLIC "-Wl,--whole-archive" "$<TARGET_FILE:gprobe_ubpf_vm>" "-Wl,--no-whole-archive")
  target_link_libraries(gprobe-syscall-server PUBLIC gprobe_ubpf_vm)
endif()

if(${GPROBE_LLVM_JIT})
  add_dependencies(gprobe-syscall-server gprobe_llvm_vm llvmbpf_vm)
  target_link_libraries(gprobe-syscall-server PUBLIC gprobe_llvm_vm)
  target_sources(gprobe-syscall-server PRIVATE $<TARGET_OBJECTS:gprobe_llvm_vm_obj>)
endif()

target_link_libraries(gprobe-syscall-server PUBLIC
    runtime
    -lpthread
    -lm
    -ldl
    spdlog::spdlog)

add_dependencies(gprobe-syscall-server spdlog::spdlog)

target_include_directories(gprobe-syscall-server
    PUBLIC
    "../include"
    "../../vm"
    "../../third_party/libbpf/include/uapi"
    ${SPDLOG_INCLUDE}
)

if(${GPROBE_BUILD_WITH_LIBBPF})
target_include_directories(gprobe-syscall-server PUBLIC
    "../../third_party/libbpf/include"
)
endif()

set_target_properties(gprobe-syscall-server PROPERTIES CXX_STANDARD 20 LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/syscall-server.version)

if(UNIX AND NOT APPLE)
target_link_options(gprobe-syscall-server PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/syscall-server.version)
endif()

if(${ENABLE_EBPF_VERIFIER})
    add_dependencies(gprobe-syscall-server gprobe-verifier)
    target_link_libraries(gprobe-syscall-server PRIVATE gprobe-verifier)
    target_include_directories(gprobe-syscall-server PRIVATE ${GPROBE_VERIFIER_INCLUDE})
    target_compile_definitions(gprobe-syscall-server PRIVATE ENABLE_EBPF_VERIFIER ENABLE_GPROBE_VERIFIER)
endif()

if (${TEST_LCOV}) 
    target_compile_options(gprobe-syscall-server PRIVATE -fprofile-arcs -ftest-coverage -fprofile-update=atomic)
    target_link_options(gprobe-syscall-server PRIVATE -fprofile-arcs)
endif()
