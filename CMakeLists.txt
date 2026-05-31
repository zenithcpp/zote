cmake_minimum_required(VERSION 3.20)
project(zote VERSION 0.1.0 LANGUAGES CXX)

# ISO C++23 — no exceptions, no RTTI
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Strict warnings — zero tolerance
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wconversion -Wshadow
    -Wformat=2 -Wnull-dereference
    -fstack-protector-strong
)

# ZOTE library
set(ZOTE_SOURCES
    src/engine.cpp
    src/mitre_map.cpp
    src/killchain.cpp
    src/correlation.cpp
    src/zote_engine.cpp
)

add_library(zote STATIC ${ZOTE_SOURCES})
target_include_directories(zote PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_compile_features(zote PUBLIC cxx_std_23)

# Tests
enable_testing()
find_package(Catch2 3 QUIET)

if(Catch2_FOUND)
    add_executable(test_zote
        tests/unit/test_engine.cpp
        tests/unit/test_mitre.cpp
        tests/unit/test_killchain.cpp
        tests/unit/test_correlation.cpp
    tests/unit/test_zote_engine.cpp
    )
    target_link_libraries(test_zote PRIVATE zote Catch2::Catch2WithMain)
    target_compile_features(test_zote PRIVATE cxx_std_23)
    add_test(NAME unit_zote COMMAND test_zote)
    message(STATUS "Catch2 found — tests enabled")
else()
    message(STATUS "Catch2 not found — tests disabled")
endif()

# Examples
add_executable(basic_detection      examples/basic_detection.cpp)
add_executable(threat_hunting       examples/threat_hunting.cpp)
add_executable(campaign_analysis    examples/campaign_analysis.cpp)
add_executable(confidence_scoring   examples/confidence_scoring.cpp)
target_link_libraries(basic_detection   PRIVATE zote)
target_link_libraries(threat_hunting     PRIVATE zote)
target_link_libraries(campaign_analysis  PRIVATE zote)
target_link_libraries(confidence_scoring PRIVATE zote)
target_compile_features(basic_detection PRIVATE cxx_std_23)

message(STATUS "")
message(STATUS "ZOTE — zenithcpp Open Source Threat Engine")
message(STATUS "  Version:      ${PROJECT_VERSION}")
message(STATUS "  Standard:     C++23")
message(STATUS "  Dependencies: NONE")
message(STATUS "")
