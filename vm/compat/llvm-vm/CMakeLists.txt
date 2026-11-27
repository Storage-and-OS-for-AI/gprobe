add_library(gprobe_llvm_vm_obj OBJECT compat_llvm.cpp)

add_dependencies(gprobe_llvm_vm_obj llvmbpf_vm spdlog::spdlog gprobe_vm_compat)

add_library(gprobe_llvm_vm STATIC $<TARGET_OBJECTS:gprobe_llvm_vm_obj>)
target_link_libraries(gprobe_llvm_vm PUBLIC gprobe_vm_compat spdlog::spdlog llvmbpf_vm)

target_include_directories(gprobe_llvm_vm_obj PRIVATE ../../llvm-jit/include ${CMAKE_CURRENT_SOURCE_DIR} ${SPDLOG_INCLUDE} ../include)

if(GPROBE_BUILD_WITH_LIBBPF)
  add_subdirectory(../../llvm-jit ${CMAKE_CURRENT_BINARY_DIR}/llvm-jit)
else()
  add_subdirectory(../../llvm-jit ${CMAKE_CURRENT_BINARY_DIR}/llvm-jit EXCLUDE_FROM_ALL)
endif()
