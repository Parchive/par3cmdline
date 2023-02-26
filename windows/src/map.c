// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "blake3/blake3.h"
#include "libpar3.h"
#include "hash.h"


// map input file slices into input blocks without slide search
int map_input_block(PAR3_CTX *par3_ctx)
{
	uint8_t *work_buf, buf_tail[40], buf_hash[16];
	int progress_old, progress_now;
	uint32_t num, num_pack, input_file_count;
	uint32_t chunk_count, chunk_index, chunk_num;
	int64_t find_index, previous_index, tail_offset;
	uint64_t block_size, tail_size, file_offset;
	uint64_t block_count, block_index;
	uint64_t slice_index, index, last_index;
	uint64_t crc, num_dedup;
	uint64_t progress_total, progress_step;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_p, *chunk_list;
	PAR3_SLICE_CTX *slice_p, *slice_list;
	PAR3_BLOCK_CTX *block_p, *block_list;
	PAR3_CMP_CTX *crc_list;
	FILE *fp;
	blake3_hasher hasher;
	time_t time_old, time_now;
	clock_t clock_now;

	// Copy variables from context to local.
	input_file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	if ( (input_file_count == 0) || (block_size == 0) || (block_count == 0) )
		return RET_LOGIC_ERROR;

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

	// When no slide search, number of input file slice is same as number of input blocks.
	// Deduplication against full size blocks only.
	slice_p = malloc(sizeof(PAR3_SLICE_CTX) * block_count);
	if (slice_p == NULL){
		perror("Failed to allocate memory for input file slices");
		return RET_MEMORY_ERROR;
	}
	slice_list = slice_p;
	par3_ctx->slice_list = slice_p;

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

	// Allocate memory to store file data temporary.
	work_buf = malloc(block_size);
	if (work_buf == NULL){
		perror("Failed to allocate memory for input file data");
		return RET_MEMORY_ERROR;
	}

	if (par3_ctx->noise_level >= 0){
		printf("Computing hash:\n");
		progress_total = par3_ctx->total_file_size;
		progress_step = 0;
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}

	// Read data of input files on memory
	num_dedup = 0;
	num_pack = 0;
	chunk_index = 0;
	block_index = 0;
	slice_index = 0;
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

		// First chunk in this file
		previous_index = -4;
		file_p->chunk = chunk_index;	// There is at least one chunk in each file.
		chunk_p->size = 0;
		chunk_p->block = 0;
		chunk_num = 0;

		// Read full size blocks
		file_offset = 0;
		while (file_offset + block_size <= file_p->size){
			// read full block from input file
			if (fread(work_buf, 1, (size_t)block_size, fp) != (size_t)block_size){
				perror("Failed to read full size chunk on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
				progress_step += block_size;
				time_now = time(NULL);
				if (time_now != time_old){
					time_old = time_now;
					progress_now = (int)((progress_step * 1000) / progress_total);
					if (progress_now != progress_old){
						progress_old = progress_now;
						printf("%d.%d%%\r", progress_now / 10, progress_now % 10);	// 0.0% ~ 100.0%
					}
				}
			}

			// calculate CRC-64 of the first 16 KB
			if (file_offset + block_size < 16384){
				file_p->crc = crc64(work_buf, (size_t)block_size, file_p->crc);
			} else if (file_offset < 16384){
				file_p->crc = crc64(work_buf, (size_t)(16384 - file_offset), file_p->crc);
			}
			blake3_hasher_update(&hasher, work_buf, (size_t)block_size);

			// Compare current CRC-64 with previous blocks.
			crc = crc64(work_buf, (size_t)block_size, 0);
			find_index = crc_list_compare(par3_ctx, crc, work_buf, buf_hash);
			//printf("find_index = %I64d, previous_index = %I64d\n", find_index, previous_index);
			if (find_index < 0){	// No match
				// Add full size block into list
				crc_list_add(par3_ctx, crc, block_index);

				// set block info
				block_p->slice = slice_index;
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

				// set slice info
				slice_p->chunk = chunk_index;
				slice_p->block = block_index;
				if (par3_ctx->noise_level >= 2){
					printf("new block[%2I64u] : slice[%2I64u] chunk[%2u] file %d, offset %I64u\n",
							block_index, slice_index, chunk_index, num, file_offset);
				}

				block_p++;
				block_index++;

			} else {	// Match with a previous block
				// update the last slice info of previous block
				index = block_list[find_index].slice;
				while (slice_list[index].next != -1){
					index = slice_list[index].next;
				}
				//printf("first index = %I64u, same = %I64u, slice_index = %I64u\n", block_list[find_index].slice, index, slice_index);
				slice_list[index].next = slice_index;

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

				// set slice info
				slice_p->chunk = chunk_index;
				slice_p->block = find_index;
				if (par3_ctx->noise_level >= 2){
					printf("old block[%2I64d] : slice[%2I64u] chunk[%2u] file %d, offset %I64u\n",
							find_index, slice_index, chunk_index, num, file_offset);
				}

				// set chunk info
				chunk_p->size += block_size;
				previous_index = find_index;
				num_dedup++;
			}

			// set common slice info
			slice_p->file = num;
			slice_p->offset = file_offset;
			slice_p->size = block_size;
			slice_p->tail_offset = 0;
			slice_p->next = -1;

			// prepare next slice info
			slice_p++;
			slice_index++;

			file_offset += block_size;
		}

		// Calculate size of chunk tail, and read it.
		tail_size = file_p->size - file_offset;
		//printf("tail_size = %I64u, file size = %I64u, offset %I64u\n", tail_size, file_p->size, file_offset);
		if (tail_size >= 40){
			// read chunk tail from input file on temporary block
			if (fread(work_buf, 1, (size_t)tail_size, fp) != (size_t)tail_size){
				perror("Failed to read tail chunk on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
				progress_step += tail_size;
				time_now = time(NULL);
				if (time_now != time_old){
					time_old = time_now;
					progress_now = (int)((progress_step * 1000) / progress_total);
					if (progress_now != progress_old){
						progress_old = progress_now;
						printf("%d.%d%%\r", progress_now / 10, progress_now % 10);	// 0.0% ~ 100.0%
					}
				}
			}

			// calculate checksum of chunk tail
			chunk_p->tail_crc = crc64(work_buf, 40, 0);
			blake3(work_buf, (size_t)tail_size, chunk_p->tail_hash);

			// search existing tails of same data
			tail_offset = 0;
			for (index = 0; index < slice_index; index++){
				//printf("tail size = %I64u\n", slice_list[index].size);
				if (slice_list[index].size == tail_size){	// same size tail
					//printf("crc = 0x%016I64x, 0x%016I64x chunk[%2u]\n", chunk_p->tail_crc, chunk_list[slice_list[index].chunk].tail_crc, slice_list[index].chunk);
					if (chunk_p->tail_crc == chunk_list[slice_list[index].chunk].tail_crc){
						if (memcmp(chunk_p->tail_hash, chunk_list[slice_list[index].chunk].tail_hash, 16) == 0){
							tail_offset = -1;

							// find the last slice info in the block
							last_index = index;
							while (slice_list[last_index].next != -1){
								last_index = slice_list[last_index].next;
							}
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

						// find the last slice info in the block
						last_index = block_list[index].slice;
						while (slice_list[last_index].next != -1){
							last_index = slice_list[last_index].next;
						}
						break;
					}
				}
			}
			//printf("tail_offset = %I64d\n", tail_offset);

			if (tail_offset < 0){	// Same data as previous tail
				if (par3_ctx->noise_level >= 2){
					printf("o t block[%2I64u] : slice[%2I64u] chunk[%2u] file %d, offset %I64u, tail size %I64u, offset %I64u\n",
							slice_list[index].block, slice_index, chunk_index, num, file_offset, tail_size, slice_list[index].tail_offset);
				}
				slice_list[last_index].next = slice_index;	// These same tails have same offset and size.

				// set slice info
				slice_p->block = slice_list[index].block;
				slice_p->tail_offset = slice_list[index].tail_offset;

				// set chunk tail info
				chunk_p->tail_block = slice_p->block;
				chunk_p->tail_offset = slice_p->tail_offset;
				num_dedup++;

			} else if (tail_offset == 0){	// Put tail in new block
				if (par3_ctx->noise_level >= 2){
					printf("n t block[%2I64u] : slice[%2I64u] chunk[%2u] file %d, offset %I64u, tail size %I64u\n",
							block_index, slice_index, chunk_index, num, file_offset, tail_size);
				}

				// set slice info
				slice_p->block = block_index;
				slice_p->tail_offset = 0;

				// set chunk tail info
				chunk_p->tail_block = block_index;
				chunk_p->tail_offset = 0;

				// set block info (block for tails don't store checksum)
				block_p->slice = slice_index;
				block_p->size = tail_size;
				block_p->crc = crc64(work_buf, (size_t)tail_size, 0);
				block_p->state = 2;
				block_p++;
				block_index++;

			} else {	// Put tail after another tail
				if (par3_ctx->noise_level >= 2){
					printf("a t block[%2I64u] : slice[%2I64u] chunk[%2u] file %d, offset %I64u, tail size %I64u, offset %I64d\n",
							index, slice_index, chunk_index, num, file_offset, tail_size, tail_offset);
				}
				slice_list[last_index].next = slice_index;	// update "next" item in the previous tail

				// set slice info
				slice_p->block = index;
				slice_p->tail_offset = tail_offset;

				// set chunk tail info
				chunk_p->tail_block = index;
				chunk_p->tail_offset = tail_offset;
				num_pack++;

				// update block info
				block_list[slice_p->block].size = tail_offset + tail_size;
				block_list[slice_p->block].crc = crc64(work_buf, (size_t)tail_size, block_list[slice_p->block].crc);
			}

			// calculate CRC-64 of the first 16 KB
			if (file_offset + tail_size < 16384){
				file_p->crc = crc64(work_buf, (size_t)tail_size, file_p->crc);
			} else if (file_offset < 16384){
				file_p->crc = crc64(work_buf, (size_t)(16384 - file_offset), file_p->crc);
			}
			blake3_hasher_update(&hasher, work_buf, (size_t)tail_size);

			// set common slice info
			slice_p->file = num;
			slice_p->offset = file_offset;
			slice_p->size = tail_size;
			slice_p->chunk = chunk_index;
			slice_p->next = -1;
			slice_p++;
			slice_index++;

		} else if (tail_size > 0){
			// When tail size is 1~39 bytes, it's saved in File Packet.
			if (fread(buf_tail, 1, (size_t)tail_size, fp) != (size_t)tail_size){
				perror("Failed to read tail chunk on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			memset(buf_tail + tail_size, 0, 40 - tail_size);	// zero fill the rest bytes
			if (par3_ctx->noise_level >= 2){
				printf("    block no  : slice no  chunk[%2u] file %d, offset %I64u, tail size %I64u\n",
						chunk_index, num, file_offset, tail_size);
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
				progress_step += tail_size;
				time_now = time(NULL);
				if (time_now != time_old){
					time_old = time_now;
					progress_now = (int)((progress_step * 1000) / progress_total);
					if (progress_now != progress_old){
						progress_old = progress_now;
						printf("%d.%d%%\r", progress_now / 10, progress_now % 10);	// 0.0% ~ 100.0%
					}
				}
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

	// Release temporary buffer.
	free(crc_list);
	par3_ctx->crc_list = NULL;
	par3_ctx->crc_count = 0;
	free(work_buf);
	par3_ctx->work_buf = NULL;

	if (par3_ctx->noise_level >= 0){
		if (progress_step < progress_total)
			printf("Didn't finish progress. %I64u / %I64u\n", progress_step, progress_total);
		clock_now = clock() - clock_now;
		printf("done in %.1f seconds.\n", (double)clock_now / CLOCKS_PER_SEC);
		printf("\n");
	}

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

	// Check actual number of slice info
	if (slice_index != block_count){
		printf("Number of input file slices = %I64u (max %I64u)\n", slice_index, block_count);
		return RET_LOGIC_ERROR;
	}
	par3_ctx->slice_count = slice_index;

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
