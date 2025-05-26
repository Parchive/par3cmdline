cmake_minimum_required(VERSION 3.16)

project("Par3" VERSION 0.1
    DESCRIPTION "Reference implementation of Parity Volume Set Specification 3.0"
    LANGUAGES C CXX)

set(CMAKE_C_FLAGS "-std=c99 -Wall -Wextra -Werror=implicit-function-declaration")
set(CMAKE_CXX_FLAGS "-std=c++20 -Wall -Wextra")

add_subdirectory(blake3)
add_subdirectory(leopard)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(platform/linux)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_subdirectory(platform/windows)
else()
    message(SEND_ERROR "Unsupported system $CMAKE_SYSTEM_NAME")
endif()

include_directories(.)

add_subdirectory(libpar3)
add_subdirectory(par3cmd)
