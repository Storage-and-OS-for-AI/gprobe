function(find_rocm)
    if(NOT GPROBE_ROCM_ROOT)
        message(FATAL_ERROR "To use ROCm attach, set GPROBE_ROCM_ROOT to the root of ROCm installation, such as /opt/rocm-6.4.1/")
    endif()
    set(ROCM_LIBRARY_PATH ${GPROBE_ROCM_ROOT}/lib PARENT_SCOPE)
    set(ROCM_INCLUDE_PATH ${GPROBE_ROCM_ROOT}/include PARENT_SCOPE)

    find_library(HIP_RUNTIME_LIB amdhip64
        HINTS ${GPROBE_ROCM_ROOT}/lib ${GPROBE_ROCM_ROOT}/core-7.14/lib
        NO_DEFAULT_PATH REQUIRED)
    find_library(HIPRTC_LIB hiprtc
        HINTS ${GPROBE_ROCM_ROOT}/lib ${GPROBE_ROCM_ROOT}/core-7.14/lib
        NO_DEFAULT_PATH REQUIRED)
    find_library(HSA_RUNTIME_LIB hsa-runtime64
        HINTS ${GPROBE_ROCM_ROOT}/lib ${GPROBE_ROCM_ROOT}/core-7.14/lib
        NO_DEFAULT_PATH REQUIRED)

    set(ROCM_LIBS ${HIP_RUNTIME_LIB} ${HIPRTC_LIB} PARENT_SCOPE)
    set(ROCM_HELPER_PATH ${CMAKE_CURRENT_SOURCE_DIR}/attach/rocm_attach_impl/trampoline/default_trampoline.hip PARENT_SCOPE)
    message(STATUS "Found ROCm libraries: ${ROCM_LIBS}")
endfunction()
