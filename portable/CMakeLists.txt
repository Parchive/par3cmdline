cmake_minimum_required(VERSION 3.16)

project("Par3" VERSION 0.1
    DESCRIPTION "Reference implementation of Parity Volume Set Specification 3.0"
    LANGUAGES C CXX)

add_compile_options(-Wall -Wextra)

add_subdirectory(blake3)
add_subdirectory(leopard)
add_subdirectory(libpar3)
add_subdirectory(par3cmd)
