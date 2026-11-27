if(NOT GPROBE_ROCM_ROOT)
	message(FATAL_ERROR "To use ROCm attach, set GPROBE_ROCM_ROOT to the root of ROCm installation, such as /opt/rocm/")
endif()

if(NOT GPROBE_ENABLE_FRIDA)
	message(FATAL_ERROR "ROCm attach requires Frida gum (set GPROBE_ENABLE_FRIDA=ON)")
endif()

set(ROCM_LIBRARY_PATH ${GPROBE_ROCM_ROOT}/lib)
set(ROCM_INCLUDE_PATH ${GPROBE_ROCM_ROOT}/include)
set(ROCM_HELPER_PATH ${CMAKE_CURRENT_SOURCE_DIR}/trampoline/default_trampoline.hip)

add_library(
	gprobe_rocm_attach_impl STATIC
	rocm_attach_impl.cpp
	rocm_attach_impl_frida_setup.cpp
	rocm_attach_private_data.cpp
)

target_compile_definitions(gprobe_rocm_attach_impl PRIVATE
	DEFAULT_ROCM_HELPER_PATH="${ROCM_HELPER_PATH}"
	DEFAULT_HIP_PIPELINE_HELPER="$<TARGET_FILE:hip-pipeline-helper>"
	__HIP_PLATFORM_AMD__=1
)

add_dependencies(
	gprobe_rocm_attach_impl
	gprobe_base_attach_impl
	spdlog::spdlog
	llvmbpf_vm
	FridaGum
	hip-pipeline-helper
)

set(ROCM_ATTACH_IMPL_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR})

find_library(AMD_HIP64_LIB NAMES amdhip64 PATHS ${ROCM_LIBRARY_PATH} REQUIRED)

target_include_directories(gprobe_rocm_attach_impl
	PRIVATE ${SPDLOG_INCLUDE}
	PRIVATE ${ROCM_INCLUDE_PATH}
	PRIVATE ${FRIDA_GUM_INSTALL_DIR}
	PUBLIC ${CMAKE_SOURCE_DIR}/runtime/
	PUBLIC ${BASE_ATTACH_IMPL_INCLUDE}
	PUBLIC ${ROCM_ATTACH_IMPL_INCLUDE}
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../vm/llvm-jit/include
)

target_link_directories(gprobe_rocm_attach_impl PUBLIC ${ROCM_LIBRARY_PATH})

target_link_libraries(gprobe_rocm_attach_impl
	PUBLIC gprobe_base_attach_impl spdlog::spdlog
	PUBLIC llvmbpf_vm
	PUBLIC ${AMD_HIP64_LIB}
	PRIVATE ${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a
)

set_property(TARGET gprobe_rocm_attach_impl PROPERTY CXX_STANDARD 20)

if(DEFINED LLVM_INCLUDE_DIRS)
	target_include_directories(gprobe_rocm_attach_impl PRIVATE ${LLVM_INCLUDE_DIRS})
endif()

get_target_property(LLVMBPF_VM_INCLUDES llvmbpf_vm INCLUDE_DIRECTORIES)
if(LLVMBPF_VM_INCLUDES)
	target_include_directories(gprobe_rocm_attach_impl PRIVATE ${LLVMBPF_VM_INCLUDES})
endif()
