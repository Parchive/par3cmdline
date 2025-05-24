add_executable(par3 main.c)

include_directories(../libpar3)

target_link_libraries(par3 PRIVATE libpar3)
