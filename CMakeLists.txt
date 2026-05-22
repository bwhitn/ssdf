cmake_minimum_required(VERSION 3.15)

project(content-sim VERSION 0.1.0 LANGUAGES C CXX)

if (NOT DEFINED CONTENT_SIM_BUILD_CLI)
    option(CONTENT_SIM_BUILD_CLI "Build the content-sim command-line tool" ON)
endif ()

if (NOT DEFINED CONTENT_SIM_BUILD_TESTS)
    option(CONTENT_SIM_BUILD_TESTS "Build content-sim unit tests" ON)
endif ()

if (NOT DEFINED CONTENT_SIM_HIGHWAYHASH_ROOT)
    set(CONTENT_SIM_HIGHWAYHASH_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/highwayhash"
        CACHE PATH "Path to a HighwayHash checkout containing c/highwayhash.c")
endif ()

set(_content_sim_highwayhash_c "${CONTENT_SIM_HIGHWAYHASH_ROOT}/c/highwayhash.c")
set(_content_sim_highwayhash_h "${CONTENT_SIM_HIGHWAYHASH_ROOT}/c/highwayhash.h")

if (NOT EXISTS "${_content_sim_highwayhash_c}" OR NOT EXISTS "${_content_sim_highwayhash_h}")
    message(
        FATAL_ERROR
            "HighwayHash was not found. Set CONTENT_SIM_HIGHWAYHASH_ROOT to a checkout containing c/highwayhash.c, "
            "or initialize the third_party/highwayhash submodule.")
endif ()

add_library(content-sim-lib STATIC ContentSim.cc ContentSim.h "${_content_sim_highwayhash_c}")
target_compile_features(content-sim-lib PUBLIC cxx_std_17)
target_include_directories(content-sim-lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CONTENT_SIM_HIGHWAYHASH_ROOT})
set_target_properties(content-sim-lib PROPERTIES OUTPUT_NAME content-sim)

if (CONTENT_SIM_BUILD_CLI)
    add_executable(content-sim main.cc)
    target_link_libraries(content-sim PRIVATE content-sim-lib)
    install(TARGETS content-sim)
endif ()

if (CONTENT_SIM_BUILD_TESTS)
    add_executable(content-sim-tests tests/content-sim-tests.cc)
    target_link_libraries(content-sim-tests PRIVATE content-sim-lib)

    include(CTest)
    add_test(NAME content-sim-tests COMMAND content-sim-tests)
endif ()
