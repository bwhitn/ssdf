cmake_minimum_required(VERSION 3.15)

project(ssdf VERSION 0.1.0 LANGUAGES C CXX)

if (NOT DEFINED SSDF_BUILD_CLI)
    option(SSDF_BUILD_CLI "Build the ssdf command-line tool" ON)
endif ()

if (NOT DEFINED SSDF_BUILD_TESTS)
    option(SSDF_BUILD_TESTS "Build ssdf unit tests" ON)
endif ()

if (NOT DEFINED SSDF_HIGHWAYHASH_ROOT)
    set(SSDF_HIGHWAYHASH_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/highwayhash"
        CACHE PATH "Path to a HighwayHash checkout containing c/highwayhash.c")
endif ()

set(_ssdf_highwayhash_c "${SSDF_HIGHWAYHASH_ROOT}/c/highwayhash.c")
set(_ssdf_highwayhash_h "${SSDF_HIGHWAYHASH_ROOT}/c/highwayhash.h")

if (NOT EXISTS "${_ssdf_highwayhash_c}" OR NOT EXISTS "${_ssdf_highwayhash_h}")
    message(
        FATAL_ERROR
            "HighwayHash was not found. Set SSDF_HIGHWAYHASH_ROOT to a checkout containing c/highwayhash.c, "
            "or initialize the third_party/highwayhash submodule.")
endif ()

add_library(ssdf-lib STATIC SSDF.cc SSDF.h "${_ssdf_highwayhash_c}")
target_compile_features(ssdf-lib PUBLIC cxx_std_17)
target_include_directories(ssdf-lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${SSDF_HIGHWAYHASH_ROOT})
set_target_properties(ssdf-lib PROPERTIES OUTPUT_NAME ssdf)

if (SSDF_BUILD_CLI)
    add_executable(ssdf main.cc)
    target_link_libraries(ssdf PRIVATE ssdf-lib)
    install(TARGETS ssdf)
endif ()

if (SSDF_BUILD_TESTS)
    add_executable(ssdf-tests tests/ssdf-tests.cc)
    target_link_libraries(ssdf-tests PRIVATE ssdf-lib)

    include(CTest)
    add_test(NAME ssdf-tests COMMAND ssdf-tests)
endif ()
