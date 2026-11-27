add_library(
    gprobe_simple_attach_impl STATIC
    ./simple_attach_impl.cpp
)

add_dependencies(gprobe_simple_attach_impl gprobe_base_attach_impl spdlog::spdlog)
set(SIMPLE_ATTACH_IMPL_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR} CACHE STRING "Include path of simple attach impl")

target_include_directories(gprobe_simple_attach_impl PRIVATE ${SPDLOG_INCLUDE} ${SIMPLE_ATTACH_IMPL_INCLUDE} PUBLIC ${BASE_ATTACH_IMPL_INCLUDE})

target_link_libraries(gprobe_simple_attach_impl PUBLIC gprobe_base_attach_impl spdlog::spdlog)
