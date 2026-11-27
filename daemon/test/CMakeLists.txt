if(${ENABLE_EBPF_VERIFIER} AND NOT TARGET Catch2)
    message(STATUS "Adding Catch2 by FetchContent at gprobe-daemon")
    Include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.4.0
    )
    FetchContent_MakeAvailable(Catch2)

    # if not enable verifier, we will use the catch2 from submodule
endif()

find_package(Boost REQUIRED)

set(TEST_SOURCES
    test_daemon.cpp
    test_daemon_driver.cpp
)

add_executable(gprobe_daemon_tests ${TEST_SOURCES})
set_property(TARGET gprobe_daemon_tests PROPERTY CXX_STANDARD 20)
add_dependencies(gprobe_daemon_tests runtime gprobe-object)
target_link_libraries(gprobe_daemon_tests PRIVATE
    runtime
    gprobe-object
    Catch2::Catch2WithMain
    libgprobe_daemon
)
target_include_directories(gprobe_daemon_tests
    PRIVATE
    ${GPROBE_RUNTIME_INCLUDE}
    ${GPROBE_OBJECT_INCLUDE_DIRS}
    ${Catch2_INCLUDE}
    ${Boost_INCLUDE}
    ../
)
add_test(NAME gprobe_daemon_tests COMMAND gprobe_daemon_tests)

# These are necessary ebpf program required by the test
# set(used_ebpf_programs
# uprobe
# # replace # Not used now
# filter)
foreach(current ${used_ebpf_programs})
    set(curr_target_name gprobe_test_ebpf_prog_${current})
    add_ebpf_program_target(${curr_target_name} ${CMAKE_CURRENT_SOURCE_DIR}/assets/${current}.bpf.c ${CMAKE_CURRENT_BINARY_DIR}/${current}.bpf.o)
    add_dependencies(gprobe_runtime_tests ${curr_target_name})
    string(TOUPPER ${current} current_name_upper)
    target_compile_definitions(gprobe_runtime_tests PRIVATE EBPF_PROGRAM_PATH_${current_name_upper}=${CMAKE_CURRENT_BINARY_DIR}/${current}.bpf.o)
endforeach()
