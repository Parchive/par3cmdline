// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "common.h"


// Count how many number of map info, and allocate memory for them.
int count_map_info(PAR3_CTX *par3_ctx)
{
	uint32_t chunk_count;
	uint64_t block_size, chunk_size, tail_size;
	uint64_t block_count, map_count;
	PAR3_CHUNK_CTX *chunk_p;
	PAR3_BLOCK_CTX *block_p;

	// Copy variables from context to local.
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	chunk_count = par3_ctx->chunk_count;
	chunk_p = par3_ctx->chunk_list;
	if ( (chunk_count == 0) || (block_size == 0) || (block_count == 0) )
		return RET_LOGIC_ERROR;

	map_count = 0;
	while (chunk_count > 0){
		chunk_size = chunk_p->size;
		if (chunk_size != 0){
			if (chunk_size >= block_size){
				map_count += chunk_size / block_size;
				tail_size = chunk_size % block_size;
			} else {
				tail_size = chunk_size;
			}
			if (tail_size >= 40)
				map_count++;
		}

		chunk_p++;
		chunk_count--;
	}

	par3_ctx->map_count = map_count;
	if (par3_ctx->noise_level >= 2){
		printf("Number of map info = %I64u\n", map_count);
	}

	// Allocate memory for block and map info.
	if (par3_ctx->map_list != NULL)
		free(par3_ctx->map_list);
	par3_ctx->map_list = malloc(sizeof(PAR3_MAP_CTX) * map_count);
	if (par3_ctx->map_list == NULL){
		perror("Failed to allocate memory for mapping");
		return RET_MEMORY_ERROR;
	}
	if (par3_ctx->block_list != NULL)
		free(par3_ctx->block_list);
	par3_ctx->block_list = malloc(sizeof(PAR3_BLOCK_CTX) * block_count);
	if (par3_ctx->block_list == NULL){
		perror("Failed to allocate memory for input blocks");
		return RET_MEMORY_ERROR;
	}

	// Initialize block info.
	block_p = par3_ctx->block_list;
	while (block_count > 0){
		block_p->map = -1;
		block_p->size = 0;
		block_p->crc = 0;
		memset(block_p->hash, 0, 16);
		block_p->state = 0;

		block_p++;
		block_count--;
	}

	return 0;
}

int set_map_info(PAR3_CTX *par3_ctx)
{
	uint32_t num, num_pack, input_file_count;
	uint32_t chunk_count, chunk_index, chunk_num;
	uint64_t block_size, chunk_size;
	uint64_t block_count, file_offset, tail_offset;
	uint64_t map_count, map_index, block_index, index;
	uint64_t num_dedup;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_p;
	PAR3_MAP_CTX *map_p, *map_list;
	PAR3_BLOCK_CTX *block_list;

	// Copy variables from context to local.
	input_file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	chunk_count = par3_ctx->chunk_count;
	map_count = par3_ctx->map_count;
	block_list = par3_ctx->block_list;
	map_list = par3_ctx->map_list;
	map_p = map_list;

	num_dedup = 0;
	num_pack = 0;
	map_index = 0;
	file_p = par3_ctx->input_file_list;
	for (num = 0; num < input_file_count; num++){
		if (file_p->size == 0){	// Skip empty files.
			file_p++;
			continue;
		}

		file_offset = 0;
		chunk_index = file_p->chunk;	// index of the first chunk
		chunk_num = file_p->chunk_num;	// number of chunk descriptions
		file_p->map = map_index;		// index of the first map info
		if (par3_ctx->noise_level >= 2){
			printf("chunk = %u + %u, map = %I64u, file size = %I64u \"%s\"\n",
					chunk_index, chunk_num, map_index, file_p->size, file_p->name);
		}

		while (chunk_num > 0){	// check all chunk descriptions
			if (chunk_index >= chunk_count){
				printf("There are too many chunk descriptions. %u\n", chunk_index);
				return RET_LOGIC_ERROR;
			}
			chunk_p = par3_ctx->chunk_list + chunk_index;
			chunk_size = chunk_p->size;
			if (chunk_size != 0){
				block_index = chunk_p->block;	// index of first input block holding chunk
				//printf("chunk size = %I64u, first block = %I64u\n", chunk_size, block_index);

				while (chunk_size >= block_size){
					if (map_index >= map_count){
						printf("There are too many map info. %I64u\n", map_index);
						return RET_LOGIC_ERROR;
					}
					if (block_index >= block_count){
						printf("There are too many input blocks. %I64u\n", block_index);
						return RET_LOGIC_ERROR;
					}
					index = block_list[block_index].map;
					if (index != -1){
						// If map info was set elready, it's a same block.
						while (map_list[index].next != -1){
							index = map_list[index].next;
						}
						map_list[index].next = map_index;
						num_dedup++;
						if (par3_ctx->noise_level >= 2){
							printf("old block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u\n",
									block_index, map_index, chunk_index, num, file_offset);
						}

					} else {
						block_list[block_index].map = map_index;
						block_list[block_index].size = block_size;
						block_list[block_index].state |= 1;
						if (par3_ctx->noise_level >= 2){
							printf("new block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u\n",
									block_index, map_index, chunk_index, num, file_offset);
						}
					}

					// set map info
					map_p->chunk = chunk_index;
					map_p->file = num;
					map_p->offset = file_offset;
					map_p->size = block_size;
					map_p->block = block_index;
					map_p->tail_offset = 0;
					map_p->next = -1;
					map_p->state = 0;
					map_p++;
					map_index++;

					block_index++;
					file_offset += block_size;
					chunk_size -= block_size;
				}
				if (chunk_size >= 40){	// Chunk tail size is equal or larger than 40 bytes.
					if (map_index >= map_count){
						printf("There are too many map info. %I64u\n", map_index);
						return RET_LOGIC_ERROR;
					}
					block_index = chunk_p->tail_block;	// index of block holding tail
					if (block_index >= block_count){
						printf("There are too many input blocks. %I64u\n", block_index);
						return RET_LOGIC_ERROR;
					}
					tail_offset = chunk_p->tail_offset;
					if (tail_offset + chunk_size > block_size){
						printf("Chunk tail exceeds block size. %I64u + %I64u\n", tail_offset, chunk_size);
						return RET_LOGIC_ERROR;
					}
					//printf("tail size = %I64u, belong block = %I64u, offset = %I64u\n", chunk_size, block_index, tail_offset);

					index = block_list[block_index].map;
					if (index != -1){
						// Search map info to find same tail.
						do {
							//printf("map[%2I64u].size = %I64u, tail_offset = %I64u\n", index, map_list[index].size, map_list[index].tail_offset);
							if ( (map_list[index].size == chunk_size) && (map_list[index].tail_offset == tail_offset) ){
								break;
							}
							index = map_list[index].next;
						} while (index != -1);

						if (index != -1){
							num_dedup++;
							if (par3_ctx->noise_level >= 2){
								printf("o t block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u, tail size %I64u, offset %I64u\n",
										block_index, map_index, chunk_index, num, file_offset, chunk_size, tail_offset);
							}
						} else {
							num_pack++;
							if (block_list[block_index].size < tail_offset + chunk_size)
								block_list[block_index].size = tail_offset + chunk_size;
							if (par3_ctx->noise_level >= 2){
								printf("a t block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u, tail size %I64u, offset %I64u\n",
										block_index, map_index, chunk_index, num, file_offset, chunk_size, tail_offset);
							}
						}

						// If map info was set elready, it may be a chunk tail in the same block.
						index = block_list[block_index].map;
						while (map_list[index].next != -1){
							index = map_list[index].next;
						}
						map_list[index].next = map_index;
						//printf("map[%2I64u].next = %I64u\n", index, map_index);

					} else {
						block_list[block_index].map = map_index;
						block_list[block_index].size = tail_offset + chunk_size;
						block_list[block_index].state |= 2;
						if (par3_ctx->noise_level >= 2){
							printf("n t block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u, tail size %I64u, offset %I64u\n",
									block_index, map_index, chunk_index, num, file_offset, chunk_size, tail_offset);
						}
					}

					// set map info
					map_p->chunk = chunk_index;
					map_p->file = num;
					map_p->offset = file_offset;
					map_p->size = chunk_size;
					map_p->block = block_index;
					map_p->tail_offset = tail_offset;
					map_p->next = -1;
					map_p->state = 0;
					map_p++;
					map_index++;

				} else if (chunk_size > 0){	// Chunk tail size = 1~39 bytes.
					if (par3_ctx->noise_level >= 2){
						printf("    block no  : map no  chunk[%2u] file %d, offset %I64u, tail size %I64u\n",
								chunk_index, num, file_offset, chunk_size);
					}

				}
				file_offset += chunk_size;	// tail size
			}

			chunk_index++;	// goto next chunk
			chunk_num--;
		}

		file_p++;
	}

	// Check all blocks have map info.
	for (index = 0; index < block_count; index++){
		if (block_list[index].map == -1){
			printf("There is no map info for input block[%I64u].\n", index);
			return RET_INSUFFICIENT_DATA;
		}
	}

	// Check actual number of map info
	if (map_index != map_count){
		printf("Number of map info = %I64u (max %I64u)\n", map_index, map_count);
		return RET_LOGIC_ERROR;
	}
	if (par3_ctx->noise_level >= 0){
		printf("Tail packing = %u, Deduplication = %I64u\n", num_pack, num_dedup);
	}

	return 0;
}

