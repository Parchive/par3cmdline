include_directories(..)

add_library(libpar3
    block_check.c
    block_create.c
    block_map.c
    block_recover.c
    common.c
    file.c
    galois16.c
    galois8.c
    hash.c
    inside_zip.c
    libpar3.c
    libpar3_create.c
    libpar3_extra.c
    libpar3_inside.c
    libpar3_verify.c
    map.c
    map_inside.c
    map_simple.c
    map_slide.c
    packet_add.c
    packet_make.c
    packet_parse.c
    read.c
    reedsolomon16.c
    reedsolomon8.c
    reedsolomon.c
    repair.c
    verify.c
    verify_check.c
    write.c
    write_inside.c
    write_trial.c
)

target_link_libraries(libpar3 PRIVATE blake3 leopard platform)
