// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake3/blake3.h"
#include "libpar3.h"
#include "hash.h"


// map input files into input blocks without deduplication
int map_input_block_simple(PAR3_CTX *par3_ctx)
{
	uint8_t *input_block, *buf_p, buf_tail[40];
	uint32_t num, num_pack;
	uint32_t input_file_count, chunk_index;
	uint64_t block_size, tail_size, file_offset, tail_offset;
	uint64_t block_count, block_index, map_index, index;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_p;
	PAR3_MAP_CTX *map_p, *map_list;
	PAR3_BLOCK_CTX *block_p, *block_list;
	FILE *fp;
	blake3_hasher hasher;

	// Copy variables from context to local.
	input_file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	if ( (input_file_count == 0) || (block_size == 0) || (block_count == 0) )
		return RET_LOGIC_ERROR;

	// When no deduplication, number of chunks may be same as number of input files.
	// Note, empty file won't use Chunk Description.
	chunk_p = malloc(sizeof(PAR3_CHUNK_CTX) * input_file_count);
	if (chunk_p == NULL){
		perror("Failed to allocate memory for chunk description");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->chunk_list = chunk_p;

	// When no deduplication, number of map is same as number of input blocks.
	map_p = malloc(sizeof(PAR3_MAP_CTX) * block_count);
	if (map_p == NULL){
		perror("Failed to allocate memory for mapping");
		return RET_MEMORY_ERROR;
	}
	map_list = map_p;
	par3_ctx->map_list = map_p;

	// When no deduplication, number of input blocks is calculable.
	block_p = malloc(sizeof(PAR3_BLOCK_CTX) * block_count);
	if (block_p == NULL){
		perror("Failed to allocate memory for input blocks");
		return RET_MEMORY_ERROR;
	}
	block_list = block_p;
	par3_ctx->block_list = block_p;

	// Try to allocate all input blocks on memory
	buf_p = malloc(block_size * block_count);
	if (buf_p == NULL){
		perror("Failed to allocate memory for input file data");
		return RET_MEMORY_ERROR;
	}
	input_block = buf_p;
	par3_ctx->input_block = buf_p;

	// Read data of input files on memory
	num_pack = 0;
	chunk_index = 0;
	block_index = 0;
	map_index = 0;
	file_p = par3_ctx->input_file_list;
	for (num = 0; num < input_file_count; num++){
		blake3_hasher_init(&hasher);
		if (file_p->size == 0){	// Skip empty files.
			blake3_hasher_finalize(&hasher, file_p->hash, 16);
			file_p++;
			continue;
		}
		if (par3_ctx->noise_level >= 2){
			printf("file size = %I64u \"%s\"\n", file_p->size, file_p->name);
		}

		fp = fopen(file_p->name, "rb");
		if (fp == NULL){
			perror("Failed to open input file");
			return RET_FILE_IO_ERROR;
		}

		// When no deduplication, chunk's index is same as file's index.
		file_p->chunk = chunk_index;	// single chunk in each file
		chunk_p->size = file_p->size;	// file size = chunk size
		chunk_p->index = block_index;
		chunk_p->next = -1;

		// Read full size blocks
		file_offset = 0;
		while (file_offset + block_size <= file_p->size){
			buf_p = input_block + (block_size * block_index);

			// read full block from input file
			if (fread(buf_p, 1, (size_t)block_size, fp) != (size_t)block_size){
				perror("Failed to read full size chunk on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

			// calculate CRC-64 of the first 16 KB
			if (file_offset + block_size < 16384){
				file_p->crc = crc64(buf_p, (size_t)block_size, file_p->crc);
			} else if (file_offset < 16384){
				file_p->crc = crc64(buf_p, (size_t)(16384 - file_offset), file_p->crc);
			}
			blake3_hasher_update(&hasher, buf_p, (size_t)block_size);

			// set block info
			block_p->map = map_index;
			block_p->size = block_size;
			block_p->crc = crc64(buf_p, (size_t)block_size, 0);
			blake3(buf_p, (size_t)block_size, block_p->hash);

			// set map info
			map_p->chunk = chunk_index;
			map_p->file = num;
			map_p->offset = file_offset;
			map_p->size = block_size;
			map_p->block = block_index;
			map_p->tail_offset = 0;
			map_p->next = -1;
			if (par3_ctx->noise_level >= 2){
				printf("new block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u\n",
						block_index, map_index, chunk_index, num, file_offset);
			}
			map_p++;
			map_index++;

			file_offset += block_size;
			block_p++;
			block_index++;
		}

		// Calculate size of chunk tail, and read it.
		tail_size = file_p->size - file_offset;
		//printf("tail_size = %I64u, file size = %I64u, offset %I64u\n", tail_size, file_p->size, file_offset);
		if (tail_size >= 40){
			// read chunk tail from input file on temporary block
			buf_p = input_block + (block_size * block_index);
			if (fread(buf_p, 1, (size_t)tail_size, fp) != (size_t)tail_size){
				perror("Failed to read tail chunk on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

			// calculate checksum of chunk tail
			chunk_p->tail_crc = crc64(buf_p, 40, 0);
			blake3(buf_p, (size_t)tail_size, chunk_p->tail_hash);

			// search existing tails to check available space
			tail_offset = 0;
			for (index = 0; index < map_index; index++){
				if ( (map_list[index].next == -1) && (map_list[index].size < block_size) ){	// the last tail in the block
					if (map_list[index].tail_offset + map_list[index].size + tail_size <= block_size){
						// When tail can fit in the space, put the tail there.
						tail_offset = map_list[index].tail_offset + map_list[index].size;
						break;
					}
				}
			}
			//printf("tail_offset = %I64d\n", tail_offset);

			if (tail_offset == 0){	// Put tail in new block
				//buf_p = input_block + (block_size * block_index);
				memset(buf_p + tail_size, 0, block_size - tail_size);	// zero fill the rest bytes
				if (par3_ctx->noise_level >= 2){
					printf("n t block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u, tail size %I64u\n",
							block_index, map_index, chunk_index, num, file_offset, tail_size);
				}

				// set map info
				map_p->block = block_index;
				map_p->tail_offset = 0;

				// set chunk tail info
				chunk_p->tail_block = block_index;
				chunk_p->tail_offset = 0;

				// set block info (block for tails don't store checksum)
				block_p->map = map_index;
				block_p->size = tail_size;
				block_p++;
				block_index++;

			} else {	// Put tail after another tail
				// copy chunk tail from temporary block
				buf_p = input_block + (block_size * map_list[index].block) + tail_offset;
				memcpy(buf_p, input_block + (block_size * block_index), (size_t)tail_size);
				if (par3_ctx->noise_level >= 2){
					printf("a t block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u, tail size %I64u, offset %I64d\n",
							map_list[index].block, map_index, chunk_index, num, file_offset, tail_size, tail_offset);
				}
				map_list[index].next = map_index;	// update "next" item in the front tail

				// set map info
				map_p->block = map_list[index].block;
				map_p->tail_offset = tail_offset;

				// set chunk tail info
				chunk_p->tail_block = map_list[index].block;
				chunk_p->tail_offset = tail_offset;
				num_pack++;

				// update block info
				block_list[map_p->block].size = tail_offset + tail_size;
			}

			// calculate CRC-64 of the first 16 KB
			if (file_offset + tail_size < 16384){
				file_p->crc = crc64(buf_p, (size_t)tail_size, file_p->crc);
			} else if (file_offset < 16384){
				file_p->crc = crc64(buf_p, (size_t)(16384 - file_offset), file_p->crc);
			}
			blake3_hasher_update(&hasher, buf_p, (size_t)tail_size);

			// set common map info
			map_p->file = num;
			map_p->offset = file_offset;
			map_p->size = tail_size;
			map_p->chunk = chunk_index;
			map_p->next = -1;
			map_p++;
			map_index++;

		} else if (tail_size > 0){
			// When tail size is 1~39-bytes, it's saved in File Packet.
			if (fread(buf_tail, 1, (size_t)tail_size, fp) != (size_t)tail_size){
				perror("Failed to read tail chunk on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			memset(buf_tail + tail_size, 0, 40 - tail_size);	// zero fill the rest bytes
			if (par3_ctx->noise_level >= 2){
				printf("    block no  : map no  chunk[%2u] file %d, offset %I64u, tail size %I64u\n",
						chunk_index, num, file_offset, tail_size);
			}

			// calculate CRC-64 of the first 16 KB
			if (file_offset + tail_size < 16384){
				file_p->crc = crc64(buf_tail, (size_t)tail_size, file_p->crc);
			} else if (file_offset < 16384){
				file_p->crc = crc64(buf_tail, (size_t)(16384 - file_offset), file_p->crc);
			}
			blake3_hasher_update(&hasher, buf_tail, (size_t)tail_size);

			// copy 1 ~ 39 bytes
			memcpy(&(chunk_p->tail_crc), buf_tail, 8);
			memcpy(chunk_p->tail_hash, buf_tail + 8, 16);
			memcpy(&(chunk_p->tail_block), buf_tail + 24, 8);
			memcpy(&(chunk_p->tail_offset), buf_tail + 32, 8);
		}

		blake3_hasher_finalize(&hasher, file_p->hash, 16);
		if (fclose(fp) != 0){
			perror("Failed to close input file");
			return RET_FILE_IO_ERROR;
		}

		file_p++;
		chunk_p++;	// Each input file contains single chunk description.
		chunk_index++;
	}

	// Re-allocate memory for actual number of chunk description
	if (par3_ctx->noise_level >= 0){
		printf("Number of chunk description = %u (max %u)\n", chunk_index, input_file_count);
	}
	if (chunk_index < input_file_count){
		if (chunk_index > 0){
			chunk_p = realloc(par3_ctx->chunk_list, sizeof(PAR3_CHUNK_CTX) * chunk_index);
			if (chunk_p == NULL){
				perror("Failed to re-allocate memory for chunk description");
				return RET_MEMORY_ERROR;
			}
			par3_ctx->chunk_list = chunk_p;
		} else {
			free(par3_ctx->chunk_list);
			par3_ctx->chunk_list = NULL;
		}
	}
	par3_ctx->chunk_count = chunk_index;

	// Check actual number of map info
	if (map_index != block_count){
		printf("Number of map info = %I64u (max %I64u)\n", map_index, block_count);
		return RET_LOGIC_ERROR;
	}
	par3_ctx->map_count = map_index;

	// Update actual number of input blocks
	if (block_index < block_count){
		block_count = block_index;
		par3_ctx->block_count = block_count;

		// realloc
		block_p = realloc(par3_ctx->block_list, sizeof(PAR3_BLOCK_CTX) * block_count);
		if (block_p == NULL){
			perror("Failed to re-allocate memory for input blocks");
			return RET_MEMORY_ERROR;
		}
		par3_ctx->block_list = block_p;
	}
	if (par3_ctx->noise_level >= 0){
		printf("Actual block count = %I64u, Tail packing = %u\n\n", block_count, num_pack);
	}

	return 0;
}


// map chunk tails, when there are no input blocks.
int map_chunk_tail(PAR3_CTX *par3_ctx)
{
	uint8_t buf_tail[40];
	uint32_t num;
	uint32_t input_file_count, chunk_index;
	uint64_t tail_size;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_p;
	FILE *fp;
	blake3_hasher hasher;

	// Copy variables from context to local.
	input_file_count = par3_ctx->input_file_count;
	if (par3_ctx->block_count != 0)
		return RET_LOGIC_ERROR;

	// When no deduplication, number of chunks may be same as number of input files.
	// Note, empty file won't use Chunk Description.
	chunk_p = malloc(sizeof(PAR3_CHUNK_CTX) * input_file_count);
	if (chunk_p == NULL){
		perror("Failed to allocate memory for chunk description");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->chunk_list = chunk_p;

	// Read data of input files on memory
	chunk_index = 0;
	file_p = par3_ctx->input_file_list;
	for (num = 0; num < input_file_count; num++){
		blake3_hasher_init(&hasher);
		if (file_p->size == 0){	// Skip empty files.
			blake3_hasher_finalize(&hasher, file_p->hash, 16);
			file_p++;
			continue;
		}
		if (par3_ctx->noise_level >= 2){
			printf("file size = %I64u \"%s\"\n", file_p->size, file_p->name);
		}

		fp = fopen(file_p->name, "rb");
		if (fp == NULL){
			perror("Failed to open input file");
			return RET_FILE_IO_ERROR;
		}

		// When no deduplication, chunk's index is same as file's index.
		file_p->chunk = chunk_index;	// single chunk in each file
		chunk_p->size = file_p->size;	// file size = chunk size
		chunk_p->index = 0;
		chunk_p->next = -1;

		tail_size = file_p->size;
		// When tail size is 1~39-bytes, it's saved in File Packet.
		if (fread(buf_tail, 1, (size_t)tail_size, fp) != (size_t)tail_size){
			perror("Failed to read tail chunk on input file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		memset(buf_tail + tail_size, 0, 40 - tail_size);	// zero fill the rest bytes

		// calculate CRC-64 of the first 16 KB
		if (tail_size < 16384){
			file_p->crc = crc64(buf_tail, (size_t)tail_size, file_p->crc);
		} else {
			file_p->crc = crc64(buf_tail, 16384, file_p->crc);
		}
		blake3_hasher_update(&hasher, buf_tail, (size_t)tail_size);

		// copy 1 ~ 39 bytes
		memcpy(&(chunk_p->tail_crc), buf_tail, 8);
		memcpy(chunk_p->tail_hash, buf_tail + 8, 16);
		memcpy(&(chunk_p->tail_block), buf_tail + 24, 8);
		memcpy(&(chunk_p->tail_offset), buf_tail + 32, 8);

		blake3_hasher_finalize(&hasher, file_p->hash, 16);
		if (fclose(fp) != 0){
			perror("Failed to close input file");
			return RET_FILE_IO_ERROR;
		}

		file_p++;
		chunk_p++;	// Each input file contains single chunk description.
		chunk_index++;
	}

	// Re-allocate memory for actual number of chunk description
	if (par3_ctx->noise_level >= 0){
		printf("Number of chunk description = %u (max %u)\n\n", chunk_index, input_file_count);
	}
	if (chunk_index < input_file_count){
		if (chunk_index > 0){
			chunk_p = realloc(par3_ctx->chunk_list, sizeof(PAR3_CHUNK_CTX) * chunk_index);
			if (chunk_p == NULL){
				perror("Failed to re-allocate memory for chunk description");
				return RET_MEMORY_ERROR;
			}
			par3_ctx->chunk_list = chunk_p;
		} else {
			free(par3_ctx->chunk_list);
			par3_ctx->chunk_list = NULL;
		}
	}
	par3_ctx->chunk_count = chunk_index;

	return 0;
}

