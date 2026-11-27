if(NOT GPROBE_MACA_ROOT)
  message(FATAL_ERROR "To use MACA attach, set GPROBE_MACA_ROOT to the root of MACA installation, such as /opt/maca/")
endif()

if(NOT GPROBE_ENABLE_FRIDA)
  message(FATAL_ERROR "MACA attach requires Frida gum (set GPROBE_ENABLE_FRIDA=ON)")
endif()

set(MACA_LIBRARY_PATH ${GPROBE_MACA_ROOT}/lib)
set(MACA_INCLUDE_PATH ${GPROBE_MACA_ROOT}/include/mcr)
set(MACA_INCLUDE_PATH_EXTRA ${GPROBE_MACA_ROOT}/include)
set(MACA_HELPER_PATH ${CMAKE_CURRENT_SOURCE_DIR}/trampoline/default_trampoline.maca)

add_library(
  gprobe_maca_attach_impl STATIC
  maca_attach_impl.cpp
  maca_attach_impl_frida_setup.cpp
  maca_attach_private_data.cpp
)

target_compile_definitions(gprobe_maca_attach_impl PRIVATE
  DEFAULT_MACA_HELPER_PATH="${MACA_HELPER_PATH}"
  DEFAULT_MACA_PIPELINE_HELPER="$<TARGET_FILE:maca-pipeline-helper>"
)

add_dependencies(
  gprobe_maca_attach_impl
  gprobe_base_attach_impl
  spdlog::spdlog
  llvmbpf_vm
  FridaGum
  maca-pipeline-helper
)

set(MACA_ATTACH_IMPL_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR})

find_library(MCRUNTIME_LIB NAMES mcruntime PATHS ${MACA_LIBRARY_PATH} REQUIRED)

target_include_directories(gprobe_maca_attach_impl
  PRIVATE ${SPDLOG_INCLUDE}
  PRIVATE ${MACA_INCLUDE_PATH}
  PRIVATE ${MACA_INCLUDE_PATH_EXTRA}
  PRIVATE ${FRIDA_GUM_INSTALL_DIR}
  PUBLIC ${CMAKE_SOURCE_DIR}/runtime/
  PUBLIC ${BASE_ATTACH_IMPL_INCLUDE}
  PUBLIC ${MACA_ATTACH_IMPL_INCLUDE}
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../vm/llvm-jit/include
)

target_link_directories(gprobe_maca_attach_impl PUBLIC ${MACA_LIBRARY_PATH})

target_link_libraries(gprobe_maca_attach_impl
  PUBLIC gprobe_base_attach_impl spdlog::spdlog
  PUBLIC llvmbpf_vm
  PUBLIC ${MCRUNTIME_LIB}
  PRIVATE ${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a
)

set_property(TARGET gprobe_maca_attach_impl PROPERTY CXX_STANDARD 20)

if(DEFINED LLVM_INCLUDE_DIRS)
  target_include_directories(gprobe_maca_attach_impl PRIVATE ${LLVM_INCLUDE_DIRS})
endif()

get_target_property(LLVMBPF_VM_INCLUDES llvmbpf_vm INCLUDE_DIRECTORIES)
if(LLVMBPF_VM_INCLUDES)
  target_include_directories(gprobe_maca_attach_impl PRIVATE ${LLVMBPF_VM_INCLUDES})
endif()
