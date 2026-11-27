add_library(gprobe-agent SHARED
  agent.cpp
)

set(AGENT_DEPS spdlog::spdlog)
if(GPROBE_ENABLE_FRIDA)
  list(APPEND AGENT_DEPS FridaGum gprobe_frida_uprobe_attach_impl)
endif()
if(${GPROBE_BUILD_WITH_LIBBPF})
  list(APPEND AGENT_DEPS gprobe_syscall_trace_attach_impl)
endif()
add_dependencies(gprobe-agent ${AGENT_DEPS})

set_target_properties(gprobe-agent PROPERTIES CXX_STANDARD 20 LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/agent.version)

if(UNIX AND NOT APPLE)
  target_link_options(gprobe-agent PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/agent.version)
endif()

if(${TEST_LCOV})
  target_compile_options(gprobe-agent PRIVATE -fprofile-arcs -ftest-coverage -fprofile-update=atomic)
  target_link_options(gprobe-agent PRIVATE -fprofile-arcs)
endif()

# Force link VM compat libraries so constructor-based factory registration is retained
if(${GPROBE_UBPF_JIT})
  add_dependencies(gprobe-agent gprobe_ubpf_vm)
  target_link_options(gprobe-agent PUBLIC "-Wl,--whole-archive" "$<TARGET_FILE:gprobe_ubpf_vm>" "-Wl,--no-whole-archive")
  target_link_libraries(gprobe-agent PUBLIC gprobe_ubpf_vm)
endif()

if(${GPROBE_LLVM_JIT})
  add_dependencies(gprobe-agent gprobe_llvm_vm llvmbpf_vm)
  target_link_libraries(gprobe-agent PUBLIC gprobe_llvm_vm)
  # Statically embed the compat_llvm constructor TU to guarantee VM factory registration in LD_PRELOAD context
  target_sources(gprobe-agent PRIVATE $<TARGET_OBJECTS:gprobe_llvm_vm_obj>)
endif()

if(${GPROBE_ENABLE_CUDA_ATTACH})
  add_dependencies(gprobe-agent gprobe_llvm_vm llvmbpf_vm gprobe_vm)
  target_link_options(gprobe-agent PUBLIC "-Wl,--whole-archive" "$<TARGET_FILE:gprobe_nv_attach_impl>" "$<TARGET_FILE:gprobe_llvm_vm>" "$<TARGET_FILE:gprobe_vm>" "$<TARGET_FILE:llvmbpf_vm>" "-Wl,--no-whole-archive")
  target_link_libraries(gprobe-agent PUBLIC gprobe_nv_attach_impl)
  target_include_directories(gprobe-agent PUBLIC ${NV_ATTACH_IMPL_INCLUDE})
  set(EXTRA_LINK_LIBS gprobe_llvm_vm
    gprobe_vm
    llvmbpf_vm)
endif()

if(GPROBE_ENABLE_ROCM_ATTACH)
  add_dependencies(gprobe-agent gprobe_llvm_vm llvmbpf_vm gprobe_vm)
  target_link_options(gprobe-agent PUBLIC "-Wl,--whole-archive" "$<TARGET_FILE:gprobe_rocm_attach_impl>" "$<TARGET_FILE:gprobe_llvm_vm>" "$<TARGET_FILE:gprobe_vm>" "$<TARGET_FILE:llvmbpf_vm>" "-Wl,--no-whole-archive")
  target_link_libraries(gprobe-agent PUBLIC gprobe_rocm_attach_impl)
  target_include_directories(gprobe-agent PUBLIC ${ROCM_ATTACH_IMPL_INCLUDE})
  set(EXTRA_LINK_LIBS ${EXTRA_LINK_LIBS} gprobe_llvm_vm
    gprobe_vm
    llvmbpf_vm)
endif()

if(GPROBE_ENABLE_MACA_ATTACH)
  add_dependencies(gprobe-agent gprobe_llvm_vm llvmbpf_vm gprobe_vm)
  target_link_options(gprobe-agent PUBLIC "-Wl,--whole-archive" "$<TARGET_FILE:gprobe_maca_attach_impl>" "$<TARGET_FILE:gprobe_llvm_vm>" "$<TARGET_FILE:gprobe_vm>" "$<TARGET_FILE:llvmbpf_vm>" "-Wl,--no-whole-archive")
  target_link_libraries(gprobe-agent PUBLIC gprobe_maca_attach_impl)
  target_include_directories(gprobe-agent PUBLIC ${MACA_ATTACH_IMPL_INCLUDE})
  set(EXTRA_LINK_LIBS ${EXTRA_LINK_LIBS} gprobe_llvm_vm
    gprobe_vm
    llvmbpf_vm)
endif()

# Include directories
target_include_directories(gprobe-agent
  PRIVATE
  ../include
  ../../third_party/
  ${SPDLOG_INCLUDE}
)
if(GPROBE_ENABLE_FRIDA)
  target_include_directories(gprobe-agent PRIVATE
    ${FRIDA_GUM_INSTALL_DIR}
    ${FRIDA_UPROBE_ATTACH_IMPL_INCLUDE}
  )
endif()
if(${GPROBE_BUILD_WITH_LIBBPF})
  target_include_directories(gprobe-agent PRIVATE
    ${SYSCALL_TRACE_ATTACH_IMPL_INCLUDE}
    ${NV_ATTACH_IMPL_INCLUDE}
  )
endif()

# Link libraries
target_link_libraries(gprobe-agent
  PUBLIC
  runtime
  -lpthread
  -lm
  -ldl
  spdlog::spdlog
  ${EXTRA_LINK_LIBS}
)
if(GPROBE_ENABLE_FRIDA)
  target_link_libraries(gprobe-agent PUBLIC
    ${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a
    gprobe_frida_uprobe_attach_impl
  )
  target_compile_definitions(gprobe-agent PRIVATE GPROBE_HAVE_FRIDA_ATTACH=1)
endif()
if(${GPROBE_BUILD_WITH_LIBBPF})
  target_link_libraries(gprobe-agent PUBLIC gprobe_syscall_trace_attach_impl)
endif()

if(TARGET gprobe_trap_uprobe_attach_impl)
  add_dependencies(gprobe-agent gprobe_trap_uprobe_attach_impl)
  target_include_directories(gprobe-agent PRIVATE ${TRAP_UPROBE_ATTACH_IMPL_INCLUDE})
  target_link_libraries(gprobe-agent PUBLIC gprobe_trap_uprobe_attach_impl)
  target_compile_definitions(gprobe-agent PRIVATE GPROBE_HAVE_TRAP_UPROBE_ATTACH=1)
endif()
target_link_options(gprobe-agent PUBLIC "-Wl,-export-dynamic")
