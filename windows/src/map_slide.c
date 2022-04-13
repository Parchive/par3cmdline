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


// map input files into input blocks with slide search
int map_input_block_slide(PAR3_CTX *par3_ctx)
{
	uint8_t *input_block, *buf_p, *work_buf;
	uint8_t buf_tail[40], buf_hash[16];
	uint32_t num, num_pack, input_file_count;
	uint32_t chunk_count, chunk_index, chunk_num;
	int64_t find_index, previous_index, tail_offset;
	uint64_t block_size, tail_size, file_offset;
	uint64_t file_size, read_size, slide_offset;
	uint64_t block_count, block_index, map_count, map_index, index;
	uint64_t crc, crc_slide, window_mask, *window_table, num_dedup;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_p, *chunk_list;
	PAR3_MAP_CTX *map_p, *map_list;
	PAR3_BLOCK_CTX *block_p, *block_list;
	PAR3_CMP_CTX *crc_list;
	FILE *fp;
	blake3_hasher hasher;

	// Copy variables from context to local.
	input_file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	if ( (input_file_count == 0) || (block_size == 0) || (block_count == 0) )
		return RET_LOGIC_ERROR;

	// Table setup for slide window search of duplicated blocks.
	init_crc_slide_table(par3_ctx, 1);
	window_mask = par3_ctx->window_mask;
	window_table = par3_ctx->window_table;

	// For deduplication, allocate chunks description as 4 * number of input files.
	// Note, empty file won't use Chunk Description.
	chunk_count = input_file_count * 4;
	if (par3_ctx->noise_level >= 2){
		printf("Initial chunk count = %u (input file count = %u)\n", chunk_count, input_file_count);
	}
	chunk_p = malloc(sizeof(PAR3_CHUNK_CTX) * chunk_count);
	if (chunk_p == NULL){
		perror("Failed to allocate memory for chunk description");
		return RET_MEMORY_ERROR;
	}
	chunk_list = chunk_p;
	par3_ctx->chunk_list = chunk_p;

	// For deduplication, allocate map info as 2 * number of input blocks.
	map_count = block_count * 2;
	if (par3_ctx->noise_level >= 2){
		printf("Initial map count = %I64u (input block count = %I64u)\n", map_count, block_count);
	}
	map_p = malloc(sizeof(PAR3_MAP_CTX) * map_count);
	if (map_p == NULL){
		perror("Failed to allocate memory for mapping");
		return RET_MEMORY_ERROR;
	}
	map_list = map_p;
	par3_ctx->map_list = map_p;

	// Allocate max number of input blocks at first.
	block_p = malloc(sizeof(PAR3_BLOCK_CTX) * block_count);
	if (block_p == NULL){
		perror("Failed to allocate memory for input blocks");
		return RET_MEMORY_ERROR;
	}
	block_list = block_p;
	par3_ctx->block_list = block_p;

	// Allocate list of CRC-64 for maximum items
	crc_list = malloc(sizeof(PAR3_CMP_CTX) * block_count);
	if (crc_list == NULL){
		perror("Failed to allocate memory for comparison of CRC-64");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->crc_list = crc_list;
	par3_ctx->crc_count = 0;	// There is no item yet.

	// Allocate buffer to store file data temporary.
	work_buf = malloc(block_size * 2);
	if (work_buf == NULL){
		perror("Failed to allocate memory for temporary file data");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->work_buf = work_buf;

	// Try to allocate all input blocks on memory
	buf_p = malloc(block_size * block_count);
	if (buf_p == NULL){
		perror("Failed to allocate memory for input file data");
		return RET_MEMORY_ERROR;
	}
	input_block = buf_p;
	par3_ctx->input_block = buf_p;

	// Read data of input files on memory
	num_dedup = 0;
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

		// Read two blocks at first.
		file_size = file_p->size;
		read_size = block_size * 2;
		if (read_size > file_size)
			read_size = file_size;
		if (fread(work_buf, 1, (size_t)read_size, fp) != read_size){
			perror("Failed to read first blocks on input file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}

		// calculate CRC-64 of the first 16 KB
		if (read_size < 16384){
			file_p->crc = crc64(work_buf, (size_t)read_size, 0);
		} else {
			file_p->crc = crc64(work_buf, 16384, 0);
		}
		blake3_hasher_update(&hasher, work_buf, (size_t)read_size);

		// First chunk in this file
		previous_index = -4;
		file_p->chunk = chunk_index;	// There is at least one chunk in each file.
		chunk_p->size = 0;
		chunk_p->block = 0;
		chunk_num = 0;

		// Compare input blocks.
		if (read_size >= block_size)
			crc = crc64(work_buf, block_size, 0);
		file_offset = 0;
		while (file_offset + block_size <= file_size){

			// Compare current CRC-64 with previous blocks.
			find_index = crc_list_compare(par3_ctx, crc, work_buf, buf_hash);
			//printf("find_index = %I64d, previous_index = %I64d\n", find_index, previous_index);
			if (find_index < 0){	// No match

				if (par3_ctx->crc_count > 0){	// Slide search
					//printf("slide: file %d, offset %I64u, crc_count = %I64u\n", num, file_offset, par3_ctx->crc_count);
					crc_slide = crc;
					slide_offset = 0;
					while (slide_offset + 1 < block_size){
						crc_slide = window_mask ^ crc_slide_byte(window_mask ^ crc_slide,
								work_buf[slide_offset + block_size], work_buf[slide_offset], window_table);
						slide_offset++;
						//printf("offset = %I64u, crc = 0x%016I64x, 0x%016I64x\n", slide_offset, crc64(work_buf + slide_offset, block_size, 0), crc_slide);

						find_index = crc_list_compare(par3_ctx, crc_slide, work_buf + slide_offset, buf_hash);
						if (find_index >= 0)
							break;
					}
				}

				if (find_index >= 0){	// When same block was found while slide search.
					// Close previous chunk with tail.
					tail_size = slide_offset;
					//printf("tail_size = %I64u, offset %I64u\n", tail_size, file_offset);
					if (tail_size >= 40){
						// calculate checksum of chunk tail
						chunk_p->tail_crc = crc64(work_buf, 40, 0);
						blake3(work_buf, (size_t)tail_size, chunk_p->tail_hash);

						// search existing tails of same data
						tail_offset = 0;
						for (index = 0; index < map_index; index++){
							//printf("tail size = %I64u\n", map_list[index].size);
							if (map_list[index].size == tail_size){	// same size tail
								//printf("crc = 0x%016I64x, 0x%016I64x chunk[%2u]\n", chunk_p->tail_crc, chunk_list[map_list[index].chunk].tail_crc, map_list[index].chunk);
								if (chunk_p->tail_crc == chunk_list[map_list[index].chunk].tail_crc){
									if (memcmp(chunk_p->tail_hash, chunk_list[map_list[index].chunk].tail_hash, 16) == 0){
										tail_offset = -1;
										break;
									}
								}
							}
						}
						if (tail_offset == 0){
							// search existing blocks to check available space
							for (index = 0; index < block_index; index++){
								if (block_list[index].size + tail_size <= block_size){
									// When tail can fit in the space, put the tail there.
									tail_offset = block_list[index].size;

									// find the last map info in the block
									index = block_list[index].map;
									while (map_list[index].next != -1){
										index = map_list[index].next;
									}
									break;
								}
							}
						}
						//printf("tail_offset = %I64d\n", tail_offset);

						if (tail_offset < 0){	// Same data as previous tail
							if (par3_ctx->noise_level >= 2){
								printf("o t block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u, tail size %I64u, offset %I64u\n",
										map_list[index].block, map_index, chunk_index, num, file_offset, tail_size, map_list[index].tail_offset);
							}
							map_list[index].next = map_index;	// These same tails have same offset and size.

							// set map info
							map_p->block = map_list[index].block;
							map_p->tail_offset = map_list[index].tail_offset;

							// set chunk tail info
							chunk_p->tail_block = map_p->block;
							chunk_p->tail_offset = map_p->tail_offset;
							num_dedup++;

						} else if (tail_offset == 0){	// Put tail in new block
							// copy chunk tail work_buf to input_block
							buf_p = input_block + (block_size * block_index);
							memcpy(buf_p, work_buf, (size_t)tail_size);
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
							block_p->state = 2;
							block_p++;
							block_index++;

						} else {	// Put tail after another tail
							// copy chunk tail work_buf to input_block
							buf_p = input_block + (block_size * map_list[index].block) + tail_offset;
							memcpy(buf_p, work_buf, (size_t)tail_size);
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

						// set common map info
						map_p->file = num;
						map_p->offset = file_offset;
						map_p->size = tail_size;
						map_p->chunk = chunk_index;
						map_p->next = -1;
						map_index++;
						if (map_index >= map_count){
							map_count *= 2;
							map_p = realloc(par3_ctx->map_list, sizeof(PAR3_MAP_CTX) * map_count);
							if (map_p == NULL){
								perror("Failed to re-allocate memory for mapping");
								fclose(fp);
								return RET_MEMORY_ERROR;
							}
							map_list = map_p;
							par3_ctx->map_list = map_p;
							map_p += map_index;
						} else {
							map_p++;
						}

					} else {	// When tail size is 1~39-bytes, it's saved in File Packet.
						memcpy(buf_tail, work_buf, (size_t)tail_size);
						memset(buf_tail + tail_size, 0, 40 - tail_size);	// zero fill the rest bytes
						if (par3_ctx->noise_level >= 2){
							printf("    block no  : map no  chunk[%2u] file %d, offset %I64u, tail size %I64u\n",
									chunk_index, num, file_offset, tail_size);
						}

						// copy 1 ~ 39 bytes
						memcpy(&(chunk_p->tail_crc), buf_tail, 8);
						memcpy(chunk_p->tail_hash, buf_tail + 8, 16);
						memcpy(&(chunk_p->tail_block), buf_tail + 24, 8);
						memcpy(&(chunk_p->tail_offset), buf_tail + 32, 8);
					}
					chunk_p->size += tail_size;

					// Close chunk description
					chunk_num++;
					chunk_index++;
					if (chunk_index >= chunk_count){
						chunk_count *= 2;
						chunk_p = realloc(par3_ctx->chunk_list, sizeof(PAR3_CHUNK_CTX) * chunk_count);
						if (chunk_p == NULL){
							perror("Failed to re-allocate memory for chunk description");
							fclose(fp);
							return RET_MEMORY_ERROR;
						}
						chunk_list = chunk_p;
						par3_ctx->chunk_list = chunk_p;
						chunk_p += chunk_index;
					} else {
						chunk_p++;
					}

					// Match with a previous block while slide search
					// update the last map info of previous block
					index = block_list[find_index].map;
					while (map_list[index].next != -1){
						index = map_list[index].next;
					}
					//printf("first index = %I64u, same = %I64u, map_index = %I64u\n", block_list[find_index].map, index, map_index);
					map_list[index].next = map_index;

					// Start this chunk
					chunk_p->size = 0;
					chunk_p->block = find_index;

					// set map info
					map_p->chunk = chunk_index;
					map_p->file = num;
					map_p->offset = file_offset + slide_offset;
					map_p->size = block_size;
					map_p->block = find_index;
					map_p->tail_offset = 0;
					map_p->next = -1;
					if (par3_ctx->noise_level >= 2){
						printf("o s block[%2I64d] : map[%2I64u] chunk[%2u] file %d, offset %I64u\n",
								find_index, map_index, chunk_index, num, file_offset + slide_offset);
					}
					map_index++;
					if (map_index >= map_count){
						map_count *= 2;
						map_p = realloc(par3_ctx->map_list, sizeof(PAR3_MAP_CTX) * map_count);
						if (map_p == NULL){
							perror("Failed to re-allocate memory for mapping");
							fclose(fp);
							return RET_MEMORY_ERROR;
						}
						map_list = map_p;
						par3_ctx->map_list = map_p;
						map_p += map_index;
					} else {
						map_p++;
					}

					// set chunk info
					chunk_p->size += block_size;
					previous_index = find_index;
					num_dedup++;

					// Read remain of partial block on first position, and next block on second position.
					file_offset += slide_offset + block_size;
					if (file_offset >= file_size){
						//printf("file_offset = %I64u, file_size = %I64u, EOF\n", file_offset, file_size);
						break;
					}
					read_size = slide_offset + block_size;
					// Slide partial block to the top
					memcpy(work_buf, work_buf + slide_offset + block_size, (size_t)(block_size - slide_offset));
					if (file_offset + (block_size - slide_offset) >= file_size){
						read_size = 0;
					} else if (file_offset + block_size * 2 > file_size){
						read_size = file_size - file_offset - (block_size - slide_offset);
					}
					//printf("file_offset = %I64u, read_size = %I64u\n", file_offset, read_size);
					if (read_size > 0){
						buf_p = work_buf + (block_size - slide_offset);
						if (fread(buf_p, 1, (size_t)read_size, fp) != read_size){
							perror("Failed to read next block on input file");
							fclose(fp);
							return RET_FILE_IO_ERROR;
						}

						// calculate CRC-64 of the first 16 KB
						if (file_offset + (block_size - slide_offset) + read_size < 16384){
							file_p->crc = crc64(buf_p, (size_t)read_size, file_p->crc);
						} else if (file_offset + (block_size - slide_offset) < 16384){
							file_p->crc = crc64(buf_p, (size_t)(16384 - file_offset - (block_size - slide_offset)), file_p->crc);
						}
						blake3_hasher_update(&hasher, buf_p, (size_t)read_size);
					}

					// Calculate CRC-64 of next block.
					if (file_offset + block_size <= file_size)
						crc = crc64(work_buf, block_size, 0);

				} else {	// When same block was not found.
					// Add full size block into list
					crc_list_add(par3_ctx, crc, block_index);

					// set block info
					block_p->map = map_index;
					block_p->size = block_size;
					block_p->crc = crc;
					if (find_index == -3){
						memcpy(block_p->hash, buf_hash, 16);
					} else {
						blake3(work_buf, (size_t)block_size, block_p->hash);
					}
					block_p->state = 1;

					// set chunk info
					if ( (chunk_p->size > 0) && (previous_index >= 0) ){	// When there are old blocks already in the chunk.
						// Close previous chunk.
						chunk_num++;
						chunk_index++;
						if (chunk_index >= chunk_count){
							chunk_count *= 2;
							chunk_p = realloc(par3_ctx->chunk_list, sizeof(PAR3_CHUNK_CTX) * chunk_count);
							if (chunk_p == NULL){
								perror("Failed to re-allocate memory for chunk description");
								fclose(fp);
								return RET_MEMORY_ERROR;
							}
							chunk_list = chunk_p;
							par3_ctx->chunk_list = chunk_p;
							chunk_p += chunk_index;
						} else {
							chunk_p++;
						}
						chunk_p->size = 0;
					}
					if (chunk_p->size == 0){	// When this is the first block in the chunk.
						// Save index of starting block.
						chunk_p->block = block_index;
					}
					chunk_p->size += block_size;
					previous_index = -4;

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
					map_index++;
					if (map_index >= map_count){
						map_count *= 2;
						map_p = realloc(par3_ctx->map_list, sizeof(PAR3_MAP_CTX) * map_count);
						if (map_p == NULL){
							perror("Failed to re-allocate memory for mapping");
							fclose(fp);
							return RET_MEMORY_ERROR;
						}
						map_list = map_p;
						par3_ctx->map_list = map_p;
						map_p += map_index;
					} else {
						map_p++;
					}

					// Copy block from work_buf to input_block.
					buf_p = input_block + (block_size * block_index);
					memcpy(buf_p, work_buf, (size_t)block_size);

					block_p++;
					block_index++;

					// Read next block on second position.
					file_offset += block_size;
					if (file_offset >= file_size){
						//printf("file_offset = %I64u, file_size = %I64u, EOF\n", file_offset, file_size);
						break;
					}
					read_size = block_size;
					if (file_offset + block_size >= file_size){
						// Slide block of second position to former position.
						memcpy(work_buf, work_buf + block_size, (size_t)(file_size - file_offset));
						read_size = 0;
					} else if (file_offset + block_size * 2 > file_size){
						read_size = file_size - file_offset - block_size;
					}
					//printf("file_offset = %I64u, read_size = %I64u\n", file_offset, read_size);
					if (read_size > 0){
						// Slide block of second position to former position.
						memcpy(work_buf, work_buf + block_size, (size_t)block_size);

						if (fread(work_buf + block_size, 1, (size_t)read_size, fp) != read_size){
							perror("Failed to read next block on input file");
							fclose(fp);
							return RET_FILE_IO_ERROR;
						}

						// calculate CRC-64 of the first 16 KB
						if (file_offset + block_size + read_size < 16384){
							file_p->crc = crc64(work_buf + block_size, (size_t)read_size, file_p->crc);
						} else if (file_offset + block_size < 16384){
							file_p->crc = crc64(work_buf + block_size, (size_t)(16384 - file_offset - block_size), file_p->crc);
						}
						blake3_hasher_update(&hasher, work_buf + block_size, (size_t)read_size);
					}

					// Calculate CRC-64 of next block.
					if (file_offset + block_size <= file_size)
						crc = crc64(work_buf, block_size, 0);
				}

			} else {	// Match with a previous block
				// update the last map info of previous block
				index = block_list[find_index].map;
				while (map_list[index].next != -1){
					index = map_list[index].next;
				}
				//printf("first index = %I64u, same = %I64u, map_index = %I64u\n", block_list[find_index].map, index, map_index);
				map_list[index].next = map_index;

				if ( (chunk_p->size > 0) &&	// When there are blocks already in the chunk.
						(find_index != previous_index + 1) ){	// If found block isn't the next of previous block.

					// Close previous chunk.
					chunk_num++;
					chunk_index++;
					if (chunk_index >= chunk_count){
						chunk_count *= 2;
						chunk_p = realloc(par3_ctx->chunk_list, sizeof(PAR3_CHUNK_CTX) * chunk_count);
						if (chunk_p == NULL){
							perror("Failed to re-allocate memory for chunk description");
							fclose(fp);
							return RET_MEMORY_ERROR;
						}
						chunk_list = chunk_p;
						par3_ctx->chunk_list = chunk_p;
						chunk_p += chunk_index;
					} else {
						chunk_p++;
					}

					// Start next chunk
					chunk_p->size = 0;
				}
				if (chunk_p->size == 0){	// When this is the first block in the chunk.
					// Save index of starting block.
					chunk_p->block = find_index;
				}

				// set map info
				map_p->chunk = chunk_index;
				map_p->file = num;
				map_p->offset = file_offset;
				map_p->size = block_size;
				map_p->block = find_index;
				map_p->tail_offset = 0;
				map_p->next = -1;
				if (par3_ctx->noise_level >= 2){
					printf("old block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u\n",
							find_index, map_index, chunk_index, num, file_offset);
				}
				map_index++;
				if (map_index >= map_count){
					map_count *= 2;
					map_p = realloc(par3_ctx->map_list, sizeof(PAR3_MAP_CTX) * map_count);
					if (map_p == NULL){
						perror("Failed to re-allocate memory for mapping");
						fclose(fp);
						return RET_MEMORY_ERROR;
					}
					map_list = map_p;
					par3_ctx->map_list = map_p;
					map_p += map_index;
				} else {
					map_p++;
				}

				// set chunk info
				chunk_p->size += block_size;
				previous_index = find_index;
				num_dedup++;

				// Read next block on second position.
				file_offset += block_size;
				if (file_offset >= file_size){
					//printf("file_offset = %I64u, file_size = %I64u, EOF\n", file_offset, file_size);
					break;
				}
				read_size = block_size;
				if (file_offset + block_size >= file_size){
					// Slide block of second position to former position.
					memcpy(work_buf, work_buf + block_size, (size_t)(file_size - file_offset));
					read_size = 0;
				} else if (file_offset + block_size * 2 > file_size){
					read_size = file_size - file_offset - block_size;
				}
				//printf("file_offset = %I64u, read_size = %I64u\n", file_offset, read_size);
				if (read_size > 0){
					// Slide block of second position to former position.
					memcpy(work_buf, work_buf + block_size, (size_t)block_size);

					if (fread(work_buf + block_size, 1, (size_t)read_size, fp) != read_size){
						perror("Failed to read next block on input file");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}

					// calculate CRC-64 of the first 16 KB
					if (file_offset + block_size + read_size < 16384){
						file_p->crc = crc64(work_buf + block_size, (size_t)read_size, file_p->crc);
					} else if (file_offset + block_size < 16384){
						file_p->crc = crc64(work_buf + block_size, (size_t)(16384 - file_offset - block_size), file_p->crc);
					}
					blake3_hasher_update(&hasher, work_buf + block_size, (size_t)read_size);
				}

				// Calculate CRC-64 of next block.
				if (file_offset + block_size <= file_size)
					crc = crc64(work_buf, block_size, 0);
			}
		}

		// Calculate size of chunk tail. (tail data was read on work_buf already.)
		tail_size = file_size - file_offset;
		//printf("tail_size = %I64u, file size = %I64u, offset %I64u\n", tail_size, file_size, file_offset);
		if (tail_size >= 40){
			// calculate checksum of chunk tail
			chunk_p->tail_crc = crc64(work_buf, 40, 0);
			blake3(work_buf, (size_t)tail_size, chunk_p->tail_hash);

			// search existing tails of same data
			tail_offset = 0;
			for (index = 0; index < map_index; index++){
				//printf("tail size = %I64u\n", map_list[index].size);
				if (map_list[index].size == tail_size){	// same size tail
					//printf("crc = 0x%016I64x, 0x%016I64x chunk[%2u]\n", chunk_p->tail_crc, chunk_list[map_list[index].chunk].tail_crc, map_list[index].chunk);
					if (chunk_p->tail_crc == chunk_list[map_list[index].chunk].tail_crc){
						if (memcmp(chunk_p->tail_hash, chunk_list[map_list[index].chunk].tail_hash, 16) == 0){
							tail_offset = -1;
							break;
						}
					}
				}
			}
			if (tail_offset == 0){
				// search existing blocks to check available space
				for (index = 0; index < block_index; index++){
					if (block_list[index].size + tail_size <= block_size){
						// When tail can fit in the space, put the tail there.
						tail_offset = block_list[index].size;

						// find the last map info in the block
						index = block_list[index].map;
						while (map_list[index].next != -1){
							index = map_list[index].next;
						}
						break;
					}
				}
			}
			//printf("tail_offset = %I64d\n", tail_offset);

			if (tail_offset < 0){	// Same data as previous tail
				if (par3_ctx->noise_level >= 2){
					printf("o t block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset %I64u, tail size %I64u, offset %I64u\n",
							map_list[index].block, map_index, chunk_index, num, file_offset, tail_size, map_list[index].tail_offset);
				}
				map_list[index].next = map_index;	// These same tails have same offset and size.

				// set map info
				map_p->block = map_list[index].block;
				map_p->tail_offset = map_list[index].tail_offset;

				// set chunk tail info
				chunk_p->tail_block = map_p->block;
				chunk_p->tail_offset = map_p->tail_offset;
				num_dedup++;

			} else if (tail_offset == 0){	// Put tail in new block
				// copy chunk tail work_buf to input_block
				buf_p = input_block + (block_size * block_index);
				memcpy(buf_p, work_buf, (size_t)tail_size);
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
				block_p->state = 2;
				block_p++;
				block_index++;

			} else {	// Put tail after another tail
				// copy chunk tail work_buf to input_block
				buf_p = input_block + (block_size * map_list[index].block) + tail_offset;
				memcpy(buf_p, work_buf, (size_t)tail_size);
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

			// set common map info
			map_p->file = num;
			map_p->offset = file_offset;
			map_p->size = tail_size;
			map_p->chunk = chunk_index;
			map_p->next = -1;
			map_index++;
			if (map_index >= map_count){
				map_count *= 2;
				map_p = realloc(par3_ctx->map_list, sizeof(PAR3_MAP_CTX) * map_count);
				if (map_p == NULL){
					perror("Failed to re-allocate memory for mapping");
					fclose(fp);
					return RET_MEMORY_ERROR;
				}
				map_list = map_p;
				par3_ctx->map_list = map_p;
				map_p += map_index;
			} else {
				map_p++;
			}

		} else if (tail_size > 0){	// When tail size is 1~39-bytes, it's saved in File Packet.
			memcpy(buf_tail, work_buf, (size_t)tail_size);
			memset(buf_tail + tail_size, 0, 40 - tail_size);	// zero fill the rest bytes
			if (par3_ctx->noise_level >= 2){
				printf("    block no  : map no  chunk[%2u] file %d, offset %I64u, tail size %I64u\n",
						chunk_index, num, file_offset, tail_size);
			}

			// copy 1 ~ 39 bytes
			memcpy(&(chunk_p->tail_crc), buf_tail, 8);
			memcpy(chunk_p->tail_hash, buf_tail + 8, 16);
			memcpy(&(chunk_p->tail_block), buf_tail + 24, 8);
			memcpy(&(chunk_p->tail_offset), buf_tail + 32, 8);
		}
		chunk_p->size += tail_size;

		// Close chunk description
		if (chunk_p->size > 0){
			chunk_num++;
			chunk_index++;
			if (chunk_index >= chunk_count){
				chunk_count *= 2;
				chunk_p = realloc(par3_ctx->chunk_list, sizeof(PAR3_CHUNK_CTX) * chunk_count);
				if (chunk_p == NULL){
					perror("Failed to re-allocate memory for chunk description");
					fclose(fp);
					return RET_MEMORY_ERROR;
				}
				chunk_list = chunk_p;
				par3_ctx->chunk_list = chunk_p;
				chunk_p += chunk_index;
			} else {
				chunk_p++;
			}
		}
		file_p->chunk_num = chunk_num;

		blake3_hasher_finalize(&hasher, file_p->hash, 16);
		if (fclose(fp) != 0){
			perror("Failed to close input file");
			return RET_FILE_IO_ERROR;
		}

		file_p++;
	}

/*
	// for debug
	for (i = 0; i < par3_ctx->crc_count; i++){
		printf("crc_list[%2u] = 0x%016I64x , %I64u\n", i, crc_list[i].crc, crc_list[i].index);
	}
*/

	// Release temporary buffer.
	free(crc_list);
	par3_ctx->crc_list = NULL;
	par3_ctx->crc_count = 0;
	free(work_buf);
	par3_ctx->work_buf = NULL;

	// Re-allocate memory for actual number of chunk description
	if (par3_ctx->noise_level >= 0){
		printf("Number of chunk description = %u (max %u)\n", chunk_index, chunk_count);
	}
	if (chunk_index < chunk_count){
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

	// Re-allocate memory for actual number of map info
	if (map_index < map_count){
		if (par3_ctx->noise_level >= 1){
			printf("Number of map info = %I64u (max %I64u)\n", map_index, map_count);
		}
		if (map_index > 0){
			map_p = realloc(par3_ctx->map_list, sizeof(PAR3_MAP_CTX) * map_index);
			if (map_p == NULL){
				perror("Failed to re-allocate memory for mapping");
				return RET_MEMORY_ERROR;
			}
			par3_ctx->map_list = map_p;
		} else {
			free(par3_ctx->map_list);
			par3_ctx->map_list = NULL;
		}
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
		printf("Actual block count = %I64u, Tail packing = %u, Deduplication = %I64u\n\n", block_count, num_pack, num_dedup);
	}

	return 0;
}
