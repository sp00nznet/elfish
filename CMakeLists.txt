cmake_minimum_required(VERSION 3.16)
project(elfish_recomp C)

set(CMAKE_C_STANDARD 11)

# Gather all lifted source files
file(GLOB SEGMENT_SOURCES src/seg*.c)

# Runtime include path
include_directories(runtime)

# Build as a static library first (no main yet)
add_library(elfish_segments STATIC ${SEGMENT_SOURCES})
target_compile_options(elfish_segments PRIVATE
    -Wall
    -Wno-unused-variable
    -Wno-unused-label
    -Wno-unused-but-set-variable
)

# TSXLIB runtime stubs
add_library(elfish_runtime STATIC runtime/tsxlib_stubs.c)
target_include_directories(elfish_runtime PRIVATE runtime)

# Placeholder main for testing compilation
add_executable(elfish_test runtime/main.c)
target_link_libraries(elfish_test elfish_segments elfish_runtime m)
