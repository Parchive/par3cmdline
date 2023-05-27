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


// map input file slices into input blocks for outside ZIP file
int map_input_block_zip(PAR3_CTX *par3_ctx, int footer_size, uint64_t unprotected_size)
{
	uint8_t *work_buf, buf_tail[40];
	int progress_old, progress_now;
	uint32_t num_pack, num_dedup;
	uint32_t chunk_index, chunk_count;
	uint64_t original_file_size, data_size, slice_count;
	uint64_t block_size, tail_size, file_offset, tail_offset;
	uint64_t block_count, block_index, slice_index, tail_index;
	uint64_t progress_total, progress_step;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_p, *chunk_list;
	PAR3_SLICE_CTX *slice_p, *slice_list;
	PAR3_BLOCK_CTX *block_p, *block_list;
	FILE *fp;
	blake3_hasher hasher;
	time_t time_old, time_now;
	clock_t clock_now;

	// Copy variables from context to local.
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	if ( (par3_ctx->input_file_count != 1) || (block_size == 0) || (block_count == 0) )
		return RET_LOGIC_ERROR;

	original_file_size = par3_ctx->total_file_size;
	if (footer_size > 0){
		// It splits original file into 2 chunks and appends 2 chunks.
		// [ data chunk ] [ footer chunk ] [ unprotected chunk ] [ duplicated footer chunk ]
		data_size = original_file_size - footer_size;
		chunk_count = 4;
	} else {
		// It appends 1 chunk.
		// [ protected chunk ] [ unprotected chunk ]
		data_size = original_file_size;
		chunk_count = 2;
	}

	chunk_p = malloc(sizeof(PAR3_CHUNK_CTX) * chunk_count);
	if (chunk_p == NULL){
		perror("Failed to allocate memory for chunk description");
		return RET_MEMORY_ERROR;
	}
	chunk_list = chunk_p;
	par3_ctx->chunk_list = chunk_p;

	// Number of input file slice may be more than number of input blocks.
	slice_count = footer_size / block_size;
	if (footer_size % block_size >= 40)
		slice_count++;
	slice_count *= 2;
	slice_count += data_size / block_size;
	if (data_size % block_size >= 40)
		slice_count++;
	slice_p = malloc(sizeof(PAR3_SLICE_CTX) * slice_count);
	if (slice_p == NULL){
		perror("Failed to allocate memory for input file slices");
		return RET_MEMORY_ERROR;
	}
	slice_list = slice_p;
	par3_ctx->slice_list = slice_p;

	// Number of input blocks is calculated already.
	block_p = malloc(sizeof(PAR3_BLOCK_CTX) * block_count);
	if (block_p == NULL){
		perror("Failed to allocate memory for input blocks");
		return RET_MEMORY_ERROR;
	}
	block_list = block_p;
	par3_ctx->block_list = block_p;

	// Allocate memory to store file data temporary.
	work_buf = malloc(block_size);
	if (work_buf == NULL){
		perror("Failed to allocate memory for input data");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->work_buf = work_buf;

	if (par3_ctx->noise_level >= 0){
		printf("\nComputing hash:\n");
		progress_total = original_file_size + footer_size;
		progress_step = 0;
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}

	// Read data of input files on memory
	num_dedup = 0;
	num_pack = 0;
	tail_offset = 0;
	chunk_index = 0;
	block_index = 0;
	slice_index = 0;
	file_p = par3_ctx->input_file_list;

	blake3_hasher_init(&hasher);
	fp = fopen(file_p->name, "rb");
	if (fp == NULL){
		perror("Failed to open input file");
		return RET_FILE_IO_ERROR;
	}

	// 1st chunk is a protected chunk
	file_p->chunk = 0;
	file_p->chunk_num = chunk_count;
	chunk_p->size = data_size;
	chunk_p->block = 0;

	// Read full size blocks
	file_offset = 0;
	while (file_offset + block_size <= data_size){
		// read full block from input file
		if (fread(work_buf, 1, (size_t)block_size, fp) != (size_t)block_size){
			perror("Failed to read full size chunk on input file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}

		// Print progress percent
		if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
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

		if (original_file_size >= 16384){
			// calculate CRC-64 of the first 16 KB
			if (file_offset + block_size < 16384){
				file_p->crc = crc64(work_buf, (size_t)block_size, file_p->crc);
			} else if (file_offset < 16384){
				file_p->crc = crc64(work_buf, (size_t)(16384 - file_offset), file_p->crc);
			}
		}
		blake3_hasher_update(&hasher, work_buf, (size_t)block_size);

		// set block info
		block_p->slice = slice_index;
		block_p->size = block_size;
		block_p->crc = crc64(work_buf, (size_t)block_size, 0);
		blake3(work_buf, (size_t)block_size, block_p->hash);
		block_p->state = 1 | 64;

		// set slice info
		slice_p->chunk = chunk_index;
		slice_p->file = 0;
		slice_p->offset = file_offset;
		slice_p->size = block_size;
		slice_p->block = block_index;
		slice_p->tail_offset = 0;
		slice_p->next = -1;
		if (par3_ctx->noise_level >= 3){
			printf("new block[%2I64u] : slice[%2I64u] chunk[%2u], offset %I64u\n",
					block_index, slice_index, chunk_index, file_offset);
		}
		slice_p++;
		slice_index++;

		file_offset += block_size;
		block_p++;
		block_index++;
	}

	// Calculate size of chunk tail, and read it.
	tail_size = data_size - file_offset;
	//printf("tail_size = %I64u, file size = %I64u, offset %I64u\n", tail_size, original_file_size, file_offset);
	if (tail_size >= 40){
		// read chunk tail from input file
		if (fread(work_buf, 1, (size_t)tail_size, fp) != (size_t)tail_size){
			perror("Failed to read tail chunk on input file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}

		// Print progress percent
		if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
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

		// Put tail in new block
		if (par3_ctx->noise_level >= 3){
			printf("n t block[%2I64u] : slice[%2I64u] chunk[%2u], offset %I64u, tail size %I64u\n",
					block_index, slice_index, chunk_index, file_offset, tail_size);
		}

		// set slice info
		slice_p->block = block_index;
		slice_p->tail_offset = 0;

		// set chunk tail info
		tail_index = slice_index;
		tail_offset = tail_size;
		chunk_p->tail_block = block_index;
		chunk_p->tail_offset = 0;

		// set block info (block for tails don't store checksum)
		block_p->slice = slice_index;
		block_p->size = tail_size;
		block_p->crc = crc64(work_buf, (size_t)tail_size, 0);
		block_p->state = 2 | 64;
		block_p++;
		block_index++;

		if (original_file_size >= 16384){
			// calculate CRC-64 of the first 16 KB
			if (file_offset + tail_size < 16384){
				file_p->crc = crc64(work_buf, (size_t)tail_size, file_p->crc);
			} else if (file_offset < 16384){
				file_p->crc = crc64(work_buf, (size_t)(16384 - file_offset), file_p->crc);
			}
		}
		blake3_hasher_update(&hasher, work_buf, (size_t)tail_size);

		// set common slice info
		slice_p->file = 0;
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
		if (par3_ctx->noise_level >= 3){
			printf("    block no  : slice no  chunk[%2u], offset %I64u, tail size %I64u\n",
					chunk_index, file_offset, tail_size);
		}

		// Print progress percent
		if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
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

		if (original_file_size >= 16384){
			// calculate CRC-64 of the first 16 KB
			if (file_offset + tail_size < 16384){
				file_p->crc = crc64(buf_tail, (size_t)tail_size, file_p->crc);
			} else if (file_offset < 16384){
				file_p->crc = crc64(buf_tail, (size_t)(16384 - file_offset), file_p->crc);
			}
		}
		blake3_hasher_update(&hasher, buf_tail, (size_t)tail_size);

		// copy 1 ~ 39 bytes
		memcpy(&(chunk_p->tail_crc), buf_tail, 8);
		memcpy(chunk_p->tail_hash, buf_tail + 8, 16);
		memcpy(&(chunk_p->tail_block), buf_tail + 24, 8);
		memcpy(&(chunk_p->tail_offset), buf_tail + 32, 8);
	}
	file_offset += tail_size;
	chunk_p++;
	chunk_index++;

	// When there is footer, 2nd chunk is a protected chunk.
	if (footer_size > 0){
		//printf("file_offset = %I64d\n", file_offset);
		chunk_p->size = footer_size;
		chunk_p->block = block_index;

		// Read full size blocks
		while (file_offset + block_size <= original_file_size){
			// read full block from input file
			if (fread(work_buf, 1, (size_t)block_size, fp) != (size_t)block_size){
				perror("Failed to read full size chunk on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
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

			if (original_file_size >= 16384){
				// calculate CRC-64 of the first 16 KB
				if (file_offset + block_size < 16384){
					file_p->crc = crc64(work_buf, (size_t)block_size, file_p->crc);
				} else if (file_offset < 16384){
					file_p->crc = crc64(work_buf, (size_t)(16384 - file_offset), file_p->crc);
				}
			}
			blake3_hasher_update(&hasher, work_buf, (size_t)block_size);

			// set block info
			block_p->slice = slice_index;
			block_p->size = block_size;
			block_p->crc = crc64(work_buf, (size_t)block_size, 0);
			blake3(work_buf, (size_t)block_size, block_p->hash);
			block_p->state = 1 | 64;

			// set slice info
			slice_p->chunk = chunk_index;
			slice_p->file = 0;
			slice_p->offset = file_offset;
			slice_p->size = block_size;
			slice_p->block = block_index;
			slice_p->tail_offset = 0;
			slice_p->next = -1;
			if (par3_ctx->noise_level >= 3){
				printf("new block[%2I64u] : slice[%2I64u] chunk[%2u], offset %I64u\n",
						block_index, slice_index, chunk_index, file_offset);
			}
			slice_p++;
			slice_index++;

			file_offset += block_size;
			block_p++;
			block_index++;
		}

		// Calculate size of chunk tail, and read it.
		tail_size = original_file_size - file_offset;
		//printf("tail_size = %I64u, file size = %I64u, offset %I64u\n", tail_size, original_file_size, file_offset);
		if (tail_size >= 40){
			// read chunk tail from input file
			if (fread(work_buf, 1, (size_t)tail_size, fp) != (size_t)tail_size){
				perror("Failed to read tail chunk on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
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

			if ( (tail_offset == 0) || (tail_offset + tail_size > block_size) ){	// Put tail in new block
				if (par3_ctx->noise_level >= 3){
					printf("n t block[%2I64u] : slice[%2I64u] chunk[%2u], offset %I64u, tail size %I64u\n",
							block_index, slice_index, chunk_index, file_offset, tail_size);
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
				block_p->state = 2 | 64;
				block_p++;
				block_index++;

			} else {	// Put tail after another tail
				if (par3_ctx->noise_level >= 3){
					printf("a t block[%2I64u] : slice[%2I64u] chunk[%2u], offset %I64u, tail size %I64u, offset %I64d\n",
							slice_list[tail_index].block, slice_index, chunk_index, file_offset, tail_size, tail_offset);
				}
				slice_list[tail_index].next = slice_index;	// update "next" item in the front tail

				// set slice info
				slice_p->block = slice_list[tail_index].block;
				slice_p->tail_offset = tail_offset;

				// set chunk tail info
				chunk_p->tail_block = slice_list[tail_index].block;
				chunk_p->tail_offset = tail_offset;
				num_pack++;

				// update block info
				block_list[slice_p->block].size = tail_offset + tail_size;
				block_list[slice_p->block].crc = crc64(work_buf, (size_t)tail_size, block_list[slice_p->block].crc);
			}

			if (original_file_size >= 16384){
				// calculate CRC-64 of the first 16 KB
				if (file_offset + tail_size < 16384){
					file_p->crc = crc64(work_buf, (size_t)tail_size, file_p->crc);
				} else if (file_offset < 16384){
					file_p->crc = crc64(work_buf, (size_t)(16384 - file_offset), file_p->crc);
				}
			}
			blake3_hasher_update(&hasher, work_buf, (size_t)tail_size);

			// set common slice info
			tail_index = slice_index;
			slice_p->file = 0;
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
			if (par3_ctx->noise_level >= 3){
				printf("    block no  : slice no  chunk[%2u], offset %I64u, tail size %I64u\n",
						chunk_index, file_offset, tail_size);
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
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

			if (original_file_size >= 16384){
				// calculate CRC-64 of the first 16 KB
				if (file_offset + tail_size < 16384){
					file_p->crc = crc64(buf_tail, (size_t)tail_size, file_p->crc);
				} else if (file_offset < 16384){
					file_p->crc = crc64(buf_tail, (size_t)(16384 - file_offset), file_p->crc);
				}
			}
			blake3_hasher_update(&hasher, buf_tail, (size_t)tail_size);

			// copy 1 ~ 39 bytes
			memcpy(&(chunk_p->tail_crc), buf_tail, 8);
			memcpy(chunk_p->tail_hash, buf_tail + 8, 16);
			memcpy(&(chunk_p->tail_block), buf_tail + 24, 8);
			memcpy(&(chunk_p->tail_offset), buf_tail + 32, 8);
		}
		file_offset += tail_size;
		chunk_p++;
		chunk_index++;

		// 3rd chunk is an uprotected chunk.
		chunk_p->size = 0;
		chunk_p->block = unprotected_size;
		if (par3_ctx->noise_level >= 3){
			printf("    block no  : slice no  chunk[%2u], offset %I64u, unprotected size %I64u\n",
					chunk_index, file_offset, unprotected_size);
		}
		chunk_p++;
		chunk_index++;

		// 4th chunk is a protected chunk, which content is same as 2nd chunk.
		chunk_p->size = footer_size;
		chunk_p->block = chunk_list[1].block;
		chunk_p->tail_crc = chunk_list[1].tail_crc;
		memcpy(chunk_p->tail_hash, chunk_list[1].tail_hash, 16);
		chunk_p->tail_block = chunk_list[1].tail_block;
		chunk_p->tail_offset = chunk_list[1].tail_offset;

		// Seek to the start of 2nd chunk
		if (_fseeki64(fp, data_size, SEEK_SET) != 0){
			perror("Failed to seek input file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}

		file_offset = original_file_size + unprotected_size;
		while (file_offset + block_size <= original_file_size + unprotected_size + footer_size){
			// read full block from input file
			if (fread(work_buf, 1, (size_t)block_size, fp) != (size_t)block_size){
				perror("Failed to read full size chunk on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
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

			blake3_hasher_update(&hasher, work_buf, (size_t)block_size);

			// set slice info
			slice_p->chunk = chunk_index;
			slice_p->file = 0;
			slice_p->offset = file_offset;
			slice_p->size = block_size;
			slice_p->block = chunk_list[1].block + num_dedup;
			slice_p->tail_offset = 0;
			slice_p->next = -1;
			if (par3_ctx->noise_level >= 3){
				printf("new block[%2I64u] : slice[%2I64u] chunk[%2u], offset %I64u\n",
						chunk_list[1].block + num_dedup, slice_index, chunk_index, file_offset);
			}
			slice_p++;
			slice_index++;
			file_offset += block_size;
			num_dedup++;
		}
		tail_size = footer_size % block_size;
		if (tail_size > 0){
			// read chunk tail from input file
			if (fread(work_buf, 1, (size_t)tail_size, fp) != (size_t)tail_size){
				perror("Failed to read tail chunk on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
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

			blake3_hasher_update(&hasher, work_buf, (size_t)tail_size);
		}
		if (tail_size >= 40){
			slice_p->chunk = chunk_index;
			slice_p->file = 0;
			slice_p->offset = file_offset;
			slice_p->size = tail_size;
			slice_p->block = slice_list[tail_index].block;
			slice_p->tail_offset = slice_list[tail_index].tail_offset;
			slice_p->next = -1;
			if (par3_ctx->noise_level >= 3){
				if ( (tail_offset == 0) || (tail_offset + tail_size > block_size) ){	// Put tail in new block
					printf("n t block[%2I64u] : slice[%2I64u] chunk[%2u], offset %I64u, tail size %I64u\n",
							chunk_list[1].block + num_dedup, slice_index, chunk_index, file_offset, tail_size);
				} else {
					printf("a t block[%2I64u] : slice[%2I64u] chunk[%2u], offset %I64u, tail size %I64u, offset %I64d\n",
							slice_list[tail_index].block, slice_index, chunk_index, file_offset, tail_size, tail_offset);
				}
			}
			slice_p++;
			slice_index++;
			num_dedup++;
		} else if (tail_size > 0){
			if (par3_ctx->noise_level >= 3){
				printf("    block no  : slice no  chunk[%2u], offset %I64u, tail size %I64u\n",
						chunk_index, file_offset, tail_size);
			}
		}
		chunk_index++;

	// When there is no footer, 2nd chunk is an unprotected chunk.
	} else {
		chunk_p->size = 0;
		chunk_p->block = unprotected_size;
		if (par3_ctx->noise_level >= 3){
			printf("    block no  : slice no  chunk[%2u], offset %I64u, unprotected size %I64u\n",
					chunk_index, file_offset, unprotected_size);
		}
		chunk_index++;
	}

	blake3_hasher_finalize(&hasher, file_p->hash, 16);
	if (fclose(fp) != 0){
		perror("Failed to close input file");
		return RET_FILE_IO_ERROR;
	}

	// Release temporary buffer.
	free(work_buf);
	par3_ctx->work_buf = NULL;

	if (par3_ctx->noise_level >= 0){
		if (par3_ctx->noise_level <= 2){
			if (progress_step < progress_total)
				printf("Didn't finish progress. %I64u / %I64u\n", progress_step, progress_total);
		}
		clock_now = clock() - clock_now;
		printf("done in %.1f seconds.\n", (double)clock_now / CLOCKS_PER_SEC);
		printf("\n");
	}

	// Check actual number of chunk description
	if (par3_ctx->noise_level >= 0){
		printf("Number of chunk description = %u (max %u)\n", chunk_index, chunk_count);
	}
	if (chunk_index != chunk_count)
		return RET_LOGIC_ERROR;
	par3_ctx->chunk_count = chunk_index;

	// Check actual number of slice info
	if (slice_index != slice_count){
		printf("Number of input file slices = %I64u (max %I64u)\n", slice_index, slice_count);
		return RET_LOGIC_ERROR;
	}
	par3_ctx->slice_count = slice_index;

	// Check actual number of input blocks
	if (block_index != block_count){
		printf("Number of input blocks = %I64u (max %I64u)\n", block_index, block_count);
		return RET_LOGIC_ERROR;
	}
	if (par3_ctx->noise_level >= 0){
		printf("Actual block count = %I64u, Tail packing = %u, Deduplication = %u\n", block_count, num_pack, num_dedup);
	}

	return 0;
}

