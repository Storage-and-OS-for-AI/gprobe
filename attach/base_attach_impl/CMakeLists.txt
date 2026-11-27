add_library(gprobe_base_attach_impl INTERFACE)

set(BASE_ATTACH_IMPL_INCLUDE
    ${CMAKE_CURRENT_SOURCE_DIR}
    CACHE STRING "Include path of base_attach_impl")

target_include_directories(gprobe_base_attach_impl
                           INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

add_dependencies(gprobe_base_attach_impl spdlog::spdlog)

target_link_libraries(gprobe_base_attach_impl INTERFACE spdlog::spdlog)

