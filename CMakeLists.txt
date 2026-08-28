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

# A window, if SDL2 is available. Without it the runtime still builds and runs
# headless -- ELFISH_DUMP_FB writes a frame and ELFISH_KEYS drives the game.
find_package(SDL2 QUIET)

# TSXLIB runtime stubs
add_library(elfish_runtime STATIC runtime/tsxlib_stubs.c runtime/video_sdl.c)
if(SDL2_FOUND)
    target_compile_definitions(elfish_runtime PRIVATE ELFISH_SDL)
    target_include_directories(elfish_runtime PRIVATE ${SDL2_INCLUDE_DIRS})
    message(STATUS "SDL2 found - building with a window")
else()
    message(STATUS "SDL2 not found - building headless")
endif()
target_include_directories(elfish_runtime PRIVATE runtime)
target_compile_definitions(elfish_runtime PRIVATE
    ELFISH_GAME_DIR="${CMAKE_SOURCE_DIR}/game/ELFISH")

# Runtime entry point
add_executable(elfish_test runtime/main.c)
target_compile_definitions(elfish_test PRIVATE
    ELFISH_IMAGE_PATH="${CMAKE_SOURCE_DIR}/build_data/mem_image.bin")
target_link_libraries(elfish_test elfish_segments elfish_runtime m)
if(SDL2_FOUND)
    # Drop SDL2main: it exists to supply a main() that calls SDL_main, and this
    # program has its own (see SDL_MAIN_HANDLED in video_sdl.c).
    set(ELFISH_SDL_LIBS "")
    foreach(lib ${SDL2_LIBRARIES})
        if(NOT lib MATCHES "SDL2main")
            list(APPEND ELFISH_SDL_LIBS ${lib})
        endif()
    endforeach()
    target_link_libraries(elfish_test ${ELFISH_SDL_LIBS})

    # SDL2 is a DLL here, so put it beside the executable -- otherwise running
    # the build output depends on the compiler's bin directory being on PATH.
    find_file(SDL2_RUNTIME_DLL SDL2.dll
              HINTS ${SDL2_PREFIX}/bin ${SDL2_EXEC_PREFIX}/bin
                    ${CMAKE_C_COMPILER}/../ /c/msys64/mingw64/bin
              PATH_SUFFIXES bin)
    if(SDL2_RUNTIME_DLL)
        add_custom_command(TARGET elfish_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${SDL2_RUNTIME_DLL} $<TARGET_FILE_DIR:elfish_test>)
    endif()
endif()
