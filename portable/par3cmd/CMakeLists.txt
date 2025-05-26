add_executable(par3 main.c locale_helpers.c)

target_link_libraries(par3 PRIVATE libpar3)

install(TARGETS par3)
