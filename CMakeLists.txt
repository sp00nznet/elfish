cmake_minimum_required(VERSION 3.16)
project(elfish_recomp C)

set(CMAKE_C_STANDARD 11)

# REQUIRED: the basic-block lift emits guest loops as tail calls
# (f(cpu); return;). Tail-call optimization (-foptimize-sibling-calls, on at
# -O2) turns them into jumps; without it, guest loops grow the C stack and
# overflow. -O2 is a correctness requirement here, not just an optimization.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-O2 -foptimize-sibling-calls)

# Gather all lifted source files (segments + generated unresolved stubs)
file(GLOB SEGMENT_SOURCES src/*.c)

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

# Runtime entry point
add_executable(elfish_test runtime/main.c)
target_compile_definitions(elfish_test PRIVATE
    ELFISH_IMAGE_PATH="${CMAKE_SOURCE_DIR}/build_data/mem_image.bin")
target_link_libraries(elfish_test elfish_segments elfish_runtime m)
