
add_library(gprobe-object OBJECT
    bpf_object.cpp
  )

# frida-gum is optional: it is not built on architectures without frida
# support (riscv64). Without this guard FRIDA_GUM_INSTALL_DIR is empty and
# the link line degrades into the literal path "/libfrida-gum.a".
set(GPROBE_OBJECT_FRIDA_LIBS "")
set(GPROBE_OBJECT_FRIDA_INCLUDE "")
if(GPROBE_ENABLE_FRIDA)
  set(GPROBE_OBJECT_FRIDA_LIBS ${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a)
  set(GPROBE_OBJECT_FRIDA_INCLUDE ${FRIDA_GUM_INSTALL_DIR})
endif()
if(${GPROBE_BUILD_WITH_LIBBPF})
  add_dependencies(gprobe-object copy_headers libbpf spdlog::spdlog gprobe_vm)
  target_link_libraries(gprobe-object
    PUBLIC
    ${LIBBPF_LIBRARIES}
    ${GPROBE_OBJECT_FRIDA_LIBS}
    -lpthread
    -lm
    -ldl
    -lelf
    -lz
    spdlog::spdlog
    gprobe_vm
  )

  target_include_directories(gprobe-object PUBLIC
    ${LIBBPF_INCLUDE_DIRS}/uapi
    ${LIBBPF_INCLUDE_DIRS}
    ${GPROBE_OBJECT_FRIDA_INCLUDE}
    $<INSTALL_INTERFACE:runtime>
    $<INSTALL_INTERFACE:runtime/src>
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../src>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../vm/include>
    ${SPDLOG_INCLUDE}
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR} 
  )
else()
  add_dependencies(gprobe-object spdlog::spdlog gprobe_vm)
  target_link_libraries(gprobe-object
    PUBLIC
    ${GPROBE_OBJECT_FRIDA_LIBS}
    -lpthread
    -lm
    -ldl
    -lelf
    -lz
    spdlog::spdlog
    gprobe_vm
  )

  target_include_directories(gprobe-object PUBLIC
    ${GPROBE_OBJECT_FRIDA_INCLUDE}
    $<INSTALL_INTERFACE:runtime>
    $<INSTALL_INTERFACE:runtime/src>
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../src>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../vm/include>
    ${SPDLOG_INCLUDE}
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR} 
  )
endif()
set(GPROBE_OBJECT_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
