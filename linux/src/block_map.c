// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "common.h"


// Count how many number of input file slices, and allocate memory for them.
int count_slice_info(PAR3_CTX *par3_ctx)
{
	uint32_t chunk_count;
	uint64_t block_size, chunk_size, tail_size;
	uint64_t block_count, slice_count;
	PAR3_CHUNK_CTX *chunk_p;
	PAR3_BLOCK_CTX *block_p;
	PAR3_SLICE_CTX *slice_p;

	// Copy variables from context to local.
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	chunk_count = par3_ctx->chunk_count;
	chunk_p = par3_ctx->chunk_list;
	if ( (chunk_count == 0) || (block_size == 0) || (block_count == 0) )
		return RET_LOGIC_ERROR;

	slice_count = 0;
	while (chunk_count > 0){
		chunk_size = chunk_p->size;
		if (chunk_size != 0){
			if (chunk_size >= block_size){
				slice_count += chunk_size / block_size;
				tail_size = chunk_size % block_size;
			} else {
				tail_size = chunk_size;
			}
			if (tail_size >= 40)
				slice_count++;
		}

		chunk_p++;
		chunk_count--;
	}

	par3_ctx->slice_count = slice_count;
	if (par3_ctx->noise_level >= 2){
		printf("Number of input file slices = %"PRINT64"u\n", slice_count);
	}

	// Allocate memory for block and slice info.
	if (par3_ctx->slice_list != NULL)
		free(par3_ctx->slice_list);
	par3_ctx->slice_list = malloc(sizeof(PAR3_SLICE_CTX) * slice_count);
	if (par3_ctx->slice_list == NULL){
		perror("Failed to allocate memory for input file slices");
		return RET_MEMORY_ERROR;
	}
	if (par3_ctx->block_list != NULL)
		free(par3_ctx->block_list);
	par3_ctx->block_list = malloc(sizeof(PAR3_BLOCK_CTX) * block_count);
	if (par3_ctx->block_list == NULL){
		perror("Failed to allocate memory for input blocks");
		return RET_MEMORY_ERROR;
	}

	// Initialize slice info.
	slice_p = par3_ctx->slice_list;
	while (slice_count > 0){
		slice_p->next = -1;
		slice_p->find_name = NULL;
		slice_p->find_offset = 0;

		slice_p++;
		slice_count--;
	}

	// Initialize block info.
	block_p = par3_ctx->block_list;
	while (block_count > 0){
		block_p->slice = -1;
		block_p->size = 0;
		block_p->crc = 0;
		memset(block_p->hash, 0, 16);
		block_p->state = 0;

		block_p++;
		block_count--;
	}

	return 0;
}

int set_slice_info(PAR3_CTX *par3_ctx)
{
	uint32_t num, num_pack, input_file_count;
	uint32_t chunk_count, chunk_index, chunk_num;
	int64_t index;
	uint64_t block_size, chunk_size;
	uint64_t block_count, file_offset, tail_offset;
	uint64_t slice_count, slice_index, block_index;
	uint64_t num_dedup;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_p;
	PAR3_SLICE_CTX *slice_p, *slice_list;
	PAR3_BLOCK_CTX *block_list;

	// Copy variables from context to local.
	input_file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	chunk_count = par3_ctx->chunk_count;
	slice_count = par3_ctx->slice_count;
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;
	slice_p = slice_list;

	num_dedup = 0;
	num_pack = 0;
	slice_index = 0;
	file_p = par3_ctx->input_file_list;
	for (num = 0; num < input_file_count; num++){
		if (file_p->size == 0){	// Skip empty files.
			file_p++;
			continue;
		}

		file_offset = 0;
		chunk_index = file_p->chunk;	// index of the first chunk
		chunk_num = file_p->chunk_num;	// number of chunk descriptions
		file_p->slice = slice_index;	// index of the first slice
		if (par3_ctx->noise_level >= 2){
			printf("chunk = %u + %u, slice = %"PRINT64"u, file size = %"PRINT64"u \"%s\"\n",
					chunk_index, chunk_num, slice_index, file_p->size, file_p->name);
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
				//printf("chunk size = %"PRINT64"u, first block = %"PRINT64"u\n", chunk_size, block_index);

				while (chunk_size >= block_size){
					if (slice_index >= slice_count){
						printf("There are too many input file slices. %"PRINT64"u\n", slice_index);
						return RET_LOGIC_ERROR;
					}
					if (block_index >= block_count){
						printf("There are too many input blocks. %"PRINT64"u\n", block_index);
						return RET_LOGIC_ERROR;
					}
					index = block_list[block_index].slice;
					if (index != -1){
						// If slice info was set elready, it's a same block.
						while (slice_list[index].next != -1){
							index = slice_list[index].next;
						}
						slice_list[index].next = slice_index;
						num_dedup++;
						if (par3_ctx->noise_level >= 2){
							printf("old block[%2"PRINT64"u] : slice[%2"PRINT64"u] chunk[%2u] file %d, offset %"PRINT64"u\n",
									block_index, slice_index, chunk_index, num, file_offset);
						}

					} else {
						block_list[block_index].slice = slice_index;
						block_list[block_index].size = block_size;
						block_list[block_index].state |= 1;
						if (par3_ctx->noise_level >= 2){
							printf("new block[%2"PRINT64"u] : slice[%2"PRINT64"u] chunk[%2u] file %d, offset %"PRINT64"u\n",
									block_index, slice_index, chunk_index, num, file_offset);
						}
					}

					// set slice info
					slice_p->chunk = chunk_index;
					slice_p->file = num;
					slice_p->offset = file_offset;
					slice_p->size = block_size;
					slice_p->block = block_index;
					slice_p->tail_offset = 0;
					slice_p++;
					slice_index++;

					block_index++;
					file_offset += block_size;
					chunk_size -= block_size;
				}
				if (chunk_size >= 40){	// Chunk tail size is equal or larger than 40 bytes.
					if (slice_index >= slice_count){
						printf("There are too many input file slices. %"PRINT64"u\n", slice_index);
						return RET_LOGIC_ERROR;
					}
					block_index = chunk_p->tail_block;	// index of block holding tail
					if (block_index >= block_count){
						printf("There are too many input blocks. %"PRINT64"u\n", block_index);
						return RET_LOGIC_ERROR;
					}
					tail_offset = chunk_p->tail_offset;
					if (tail_offset + chunk_size > block_size){
						printf("Chunk tail exceeds block size. %"PRINT64"u + %"PRINT64"u\n", tail_offset, chunk_size);
						return RET_LOGIC_ERROR;
					}
					//printf("tail size = %"PRINT64"u, belong block = %"PRINT64"u, offset = %"PRINT64"u\n", chunk_size, block_index, tail_offset);

					index = block_list[block_index].slice;
					if (index != -1){
						// Search slice info to find same tail.
						do {
							//printf("slice[%2"PRINT64"u].size = %"PRINT64"u, tail_offset = %"PRINT64"u\n", index, slice_list[index].size, slice_list[index].tail_offset);
							if ( (slice_list[index].size == chunk_size) && (slice_list[index].tail_offset == tail_offset) ){
								break;
							}
							index = slice_list[index].next;
						} while (index != -1);

						if (index != -1){
							num_dedup++;
							if (par3_ctx->noise_level >= 2){
								printf("o t block[%2"PRINT64"u] : slice[%2"PRINT64"u] chunk[%2u] file %d, offset %"PRINT64"u, tail size %"PRINT64"u, offset %"PRINT64"u\n",
										block_index, slice_index, chunk_index, num, file_offset, chunk_size, tail_offset);
							}
						} else {
							num_pack++;
							if (block_list[block_index].size < tail_offset + chunk_size)
								block_list[block_index].size = tail_offset + chunk_size;
							if (par3_ctx->noise_level >= 2){
								printf("a t block[%2"PRINT64"u] : slice[%2"PRINT64"u] chunk[%2u] file %d, offset %"PRINT64"u, tail size %"PRINT64"u, offset %"PRINT64"u\n",
										block_index, slice_index, chunk_index, num, file_offset, chunk_size, tail_offset);
							}
						}

						// If slice info was set elready, it may be a chunk tail in the same block.
						index = block_list[block_index].slice;
						while (slice_list[index].next != -1){
							index = slice_list[index].next;
						}
						slice_list[index].next = slice_index;
						//printf("slice[%2"PRINT64"u].next = %"PRINT64"u\n", index, slice_index);

					} else {
						block_list[block_index].slice = slice_index;
						block_list[block_index].size = tail_offset + chunk_size;
						block_list[block_index].state |= 2;
						if (par3_ctx->noise_level >= 2){
							printf("n t block[%2"PRINT64"u] : slice[%2"PRINT64"u] chunk[%2u] file %d, offset %"PRINT64"u, tail size %"PRINT64"u, offset %"PRINT64"u\n",
									block_index, slice_index, chunk_index, num, file_offset, chunk_size, tail_offset);
						}
					}

					// set slice info
					slice_p->chunk = chunk_index;
					slice_p->file = num;
					slice_p->offset = file_offset;
					slice_p->size = chunk_size;
					slice_p->block = block_index;
					slice_p->tail_offset = tail_offset;
					slice_p++;
					slice_index++;

				} else if (chunk_size > 0){	// Chunk tail size = 1~39 bytes.
					if (par3_ctx->noise_level >= 2){
						printf("    block no  : slice no  chunk[%2u] file %d, offset %"PRINT64"u, tail size %"PRINT64"u\n",
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

	// Check every block has own slice.
	for (block_index = 0; block_index < block_count; block_index++){
		if (block_list[block_index].slice == -1){
			printf("There is no slice for input block[%"PRINT64"u].\n", block_index);
			return RET_INSUFFICIENT_DATA;
		}
	}

	// Check actual number of slices.
	if (slice_index != slice_count){
		printf("Number of input file slices = %"PRINT64"u (max %"PRINT64"u)\n", slice_index, slice_count);
		return RET_LOGIC_ERROR;
	}
	if (par3_ctx->noise_level >= 0){
		printf("Tail packing = %u, Deduplication = %"PRINT64"u\n", num_pack, num_dedup);
	}

	return 0;
}

