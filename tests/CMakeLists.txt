cmake_minimum_required(VERSION 3.14)
project(vnetif_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Fetch GoogleTest (no system package required)
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
# Don't install gtest alongside the project
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(vnetif_tests vnetif_test.cc)
target_link_libraries(vnetif_tests GTest::gtest_main)

# Run via ctest; must be invoked as root
add_test(NAME vnetif_tests COMMAND vnetif_tests)
