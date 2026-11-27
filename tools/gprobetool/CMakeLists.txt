add_executable(gprobetool
  main.cpp
)
if(${GPROBE_ENABLE_CUDA_ATTACH})
  include(../../cmake/cuda.cmake)
  find_cuda()
  target_link_directories(gprobetool PUBLIC ${CUDA_LIBRARY_PATH})
  target_include_directories(gprobetool PUBLIC ${CUDA_INCLUDE_PATH})
endif()
if(${GPROBE_BUILD_WITH_LIBBPF})
  set (LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/../../runtime/object/libbpf)
  target_include_directories(gprobetool PUBLIC
    ../../third_party/
    ../../runtime/include
    ${LIBBPF_INCLUDE_DIRS}/uapi
    ${LIBBPF_INCLUDE_DIRS}
  )

  if(${GPROBE_ENABLE_CUDA_ATTACH})
    target_link_libraries(gprobetool
      -lpthread
      -lm
      -ldl
      runtime
      gprobe-object
      ${CUDA_LIBS}
      gprobe_nv_attach_impl
    )
  else()
    target_link_libraries(gprobetool
      -lpthread
      -lm
      -ldl
      runtime
      gprobe-object
    )
  endif()
else()
  target_include_directories(gprobetool PUBLIC
    ../../third_party/
    ../../runtime/include
  )
  if(${GPROBE_ENABLE_CUDA_ATTACH})
    target_link_libraries(gprobetool
      -lpthread
      -lm
      -ldl
      runtime
      ${CUDA_LIBS}
      gprobe_nv_attach_impl
    )
  else()
    target_link_libraries(gprobetool
      -lpthread
      -lm
      -ldl
      runtime
    )
  endif()
endif()

install(TARGETS gprobetool CONFIGURATIONS Release Debug RelWithDebInfo DESTINATION ~/.gprobe)
