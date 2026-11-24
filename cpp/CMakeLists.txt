cmake_minimum_required(VERSION 3.20)
project(gatekeeper_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(GK_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(GK_BUILD_TESTS "Build the GoogleTest suite (fetches googletest)" ON)

add_library(gk_core STATIC src/sql.cpp src/policy.cpp)
target_include_directories(gk_core PUBLIC src)
target_compile_options(gk_core PUBLIC -Wall -Wextra -Wpedantic)

add_executable(gatekeeper-cpp src/main.cpp)
target_link_libraries(gatekeeper-cpp PRIVATE gk_core)

if(GK_SANITIZE)
  set(_san -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer)
  target_compile_options(gk_core PUBLIC ${_san})
  target_link_options(gk_core PUBLIC ${_san})
endif()

if(GK_BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  enable_testing()
  add_executable(gk_tests tests/test_policy.cpp)
  target_link_libraries(gk_tests PRIVATE gk_core GTest::gtest_main)
  target_compile_definitions(gk_tests PRIVATE GK_GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/golden")
  include(GoogleTest)
  gtest_discover_tests(gk_tests)
endif()
