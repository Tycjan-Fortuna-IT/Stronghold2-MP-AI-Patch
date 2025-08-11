cmake_minimum_required(VERSION 3.30...4.0 FATAL_ERROR)

project(Stronghold2MPAIPatch VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT MSVC)
    message(FATAL_ERROR "This project requires the MSVC compiler.")
endif()

set(CMAKE_SUPPRESS_REGENERATION TRUE)

set_property(GLOBAL PROPERTY PREDEFINED_TARGETS_FOLDER "")
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_compile_options(/W4 /MP)

set(SRC_FILES
    src/main.cpp
)

source_group("src" FILES ${SRC_FILES})

add_executable(${PROJECT_NAME} ${SRC_FILES})

message(STATUS "Output to: \"${CMAKE_BINARY_DIR}\"")
