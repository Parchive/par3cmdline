add_library(leopard STATIC
    leopard.cpp
    LeopardCommon.cpp
    LeopardFF8.cpp
    LeopardFF16.cpp
)

set_source_files_properties(LeopardFF8.cpp LeopardFF16.cpp PROPERTIES COMPILE_OPTIONS "-mssse3")
