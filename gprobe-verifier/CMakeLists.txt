add_library(gprobe-verifier STATIC src/gprobe-verifier.cpp src/platform-impl.cpp)
add_subdirectory(ebpf-verifier)

set_property(TARGET gprobe-verifier PROPERTY CXX_STANDARD 20)

target_include_directories(gprobe-verifier
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ebpf-verifier/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBBPF_INCLUDE_DIRS}
)

target_link_libraries(gprobe-verifier PUBLIC ebpfverifier ${LIBBPF_LIBRARIES} z elf)

add_dependencies(gprobe-verifier ebpfverifier libbpf)

set(GPROBE_VERIFIER_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/include)

set(TEST_SOURCES
    test/simple.cpp
    test/map.cpp
    test/non_kernel_helper.cpp
)

if(NOT TARGET Catch2)
    message(STATUS "Adding Catch2 by FetchContent at gprobe-verifier")
    Include(FetchContent)

    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.0.1
    )

    FetchContent_MakeAvailable(Catch2)
endif()

option(TEST_LCOV "option for lcov" OFF)
add_executable(gprobe_verifier_tests ${TEST_SOURCES})

if (${TEST_LCOV}) 
    target_compile_options(gprobe_verifier_tests PRIVATE -fprofile-arcs -ftest-coverage -fprofile-update=atomic)
endif()

add_dependencies(gprobe_verifier_tests gprobe-verifier)

if (${TEST_LCOV}) 
    target_link_options(gprobe_verifier_tests PRIVATE -lgcov)
    target_link_libraries(gprobe_verifier_tests PRIVATE gprobe-verifier Catch2::Catch2WithMain gcov)
else ()
    target_link_libraries(gprobe_verifier_tests PRIVATE gprobe-verifier Catch2::Catch2WithMain)
endif()
target_include_directories(gprobe_verifier_tests PRIVATE ${GPROBE_VERIFIER_INCLUDE})
add_test(NAME gprobe_verifier_tests COMMAND gprobe_verifier_tests)
