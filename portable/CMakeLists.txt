cmake_minimum_required(VERSION 3.16)

project("Par3" VERSION 0.1
    DESCRIPTION "Reference implementation of Parity Volume Set Specification 3.0"
    LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall)

if ( CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR
     CMAKE_CXX_COMPILER_ID STREQUAL "GNU" )
    add_compile_options(-Wextra -Wno-sign-compare)

    # Prepend so this can be overridden with CFLAGS when calling CMake:
    set(CMAKE_C_FLAGS "-Werror=implicit-function-declaration ${CMAKE_C_FLAGS}")
endif()

add_subdirectory(blake3)
add_subdirectory(leopard)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(platform/linux)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_subdirectory(platform/windows)
else()
    message(SEND_ERROR "Unsupported system ${CMAKE_SYSTEM_NAME}")
endif()

add_subdirectory(libpar3)
add_subdirectory(par3cmd)
