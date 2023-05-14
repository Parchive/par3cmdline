// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libpar3.h"
#include "common.h"
#include "galois.h"
#include "hash.h"
#include "reedsolomon.h"
#include "leopard/leopard.h"


// When it uses Reed-Solomon Erasure Codes, it tries to allocate memory for all recovery blocks.
int allocate_recovery_block(PAR3_CTX *par3_ctx)
{
	size_t alloc_size, region_size;

	// Allocate tables before blocks.
	if (par3_ctx->galois_poly == 0x1100B){	// 16-bit Galois Field (0x1100B).
		par3_ctx->galois_table = gf16_create_table(par3_ctx->galois_poly);

	} else if (par3_ctx->galois_poly == 0x11D){	// 8-bit Galois Field (0x11D).
		par3_ctx->galois_table = gf8_create_table(par3_ctx->galois_poly);

	} else {
		printf("Galois Field (0x%X) isn't supported.\n", par3_ctx->galois_poly);
		return RET_LOGIC_ERROR;
	}
	if (par3_ctx->galois_table == NULL){
		printf("Failed to create tables for Galois Field (0x%X)\n", par3_ctx->galois_poly);
		return RET_MEMORY_ERROR;
	}

	// Set memory alignment of block data to be 4.
	// Increase at least 1 byte as checksum.
	region_size = (par3_ctx->block_size + 4 + 3) & ~3;

	// Limited memory usage
	alloc_size = region_size * par3_ctx->recovery_block_count;
	if ( (par3_ctx->memory_limit > 0) && (alloc_size > par3_ctx->memory_limit) )
		return 0;

	// Allocate memory to keep recovery blocks
	par3_ctx->block_data = malloc(alloc_size);
	//par3_ctx->block_data = NULL;	// For testing another method
	if (par3_ctx->block_data != NULL){
		par3_ctx->ecc_method |= 0x8000;	// Keep all recovery blocks on memory
		if (par3_ctx->noise_level >= 2){
			printf("\nAligned size of block data = %zu\n", region_size);
			printf("Keep all recovery blocks on memory (%zu * %I64u = %zu)\n", region_size, par3_ctx->recovery_block_count, alloc_size);
		}
	}

	return 0;
}

// This supports Reed-Solomon Erasure Codes on 8-bit or 16-bit Galois Field.
// GF tables and recovery blocks were allocated already.
int create_recovery_block(PAR3_CTX *par3_ctx)
{
	uint8_t *work_buf;
	uint8_t gf_size;
	int galois_poly;
	int block_count, block_index;
	int progress_old, progress_now;
	uint32_t file_index, file_prev;
	size_t block_size, region_size;
	size_t data_size, read_size;
	size_t tail_offset, tail_gap;
	int64_t slice_index, file_offset;
	PAR3_FILE_CTX *file_list;
	PAR3_SLICE_CTX *slice_list;
	PAR3_BLOCK_CTX *block_list;
	FILE *fp;
	time_t time_old, time_now;
	clock_t clock_now;

	if (par3_ctx->recovery_block_count == 0)
		return -1;

	// GF tables and recovery blocks must be stored on memory.
	if ( (par3_ctx->galois_table == NULL) || (par3_ctx->block_data == NULL) )
		return -1;

	// Only when it uses Reed-Solomon Erasure Codes.
	if ((par3_ctx->ecc_method & 1) == 0)
		return -1;

	block_size = par3_ctx->block_size;
	block_count = (int)(par3_ctx->block_count);
	gf_size = par3_ctx->gf_size;
	galois_poly = par3_ctx->galois_poly;
	file_list = par3_ctx->input_file_list;
	slice_list = par3_ctx->slice_list;
	block_list = par3_ctx->block_list;

	// Allocate memory to read one input block and parity.
	region_size = (block_size + 4 + 3) & ~3;
	work_buf = malloc(region_size);
	if (work_buf == NULL){
		perror("Failed to allocate memory for input data");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->work_buf = work_buf;

	if (par3_ctx->noise_level >= 0){
		printf("\nComputing recovery blocks:\n");
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}

	// Reed-Solomon Erasure Codes
	file_prev = 0xFFFFFFFF;
	fp = NULL;
	for (block_index = 0; block_index < block_count; block_index++){
		// Read each input block from input files.
		data_size = block_list[block_index].size;
		if (block_list[block_index].state & 1){	// including full size data
			slice_index = block_list[block_index].slice;
			while (slice_index != -1){
				if (slice_list[slice_index].size == block_size)
					break;
				slice_index = slice_list[slice_index].next;
			}
			if (slice_index == -1){	// When there is no valid slice.
				printf("Mapping information for block[%d] is wrong.\n", block_index);
				if (fp != NULL)
					fclose(fp);
				return RET_LOGIC_ERROR;
			}

			// Read one slice from a file.
			file_index = slice_list[slice_index].file;
			file_offset = slice_list[slice_index].offset;
			read_size = data_size;
			if (par3_ctx->noise_level >= 3){
				printf("Reading %zu bytes of slice[%I64d] for input block[%d]\n", read_size, slice_index, block_index);
			}
			if ( (fp == NULL) || (file_index != file_prev) ){
				if (fp != NULL){	// Close previous input file.
					fclose(fp);
					fp = NULL;
				}
				fp = fopen(file_list[file_index].name, "rb");
				if (fp == NULL){
					perror("Failed to open Input File");
					return RET_FILE_IO_ERROR;
				}
				file_prev = file_index;
			}
			if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
				perror("Failed to seek Input File");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			if (fread(work_buf, 1, read_size, fp) != read_size){
				perror("Failed to read slice on Input File");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

		} else {	// tail data only (one tail or packed tails)
			if (par3_ctx->noise_level >= 3){
				printf("Reading %I64u bytes for input block[%d]\n", data_size, block_index);
			}
			tail_offset = 0;
			while (tail_offset < data_size){	// Read tails until data end.
				slice_index = block_list[block_index].slice;
				while (slice_index != -1){
					//printf("block = %I64u, size = %zu, offset = %zu, slice = %I64d\n", block_index, data_size, tail_offset, slice_index);
					// Even when chunk tails are overlaped, it will find tail slice of next position.
					if ( (slice_list[slice_index].tail_offset + slice_list[slice_index].size > tail_offset)
							&& (slice_list[slice_index].tail_offset <= tail_offset) ){
						break;
					}
					slice_index = slice_list[slice_index].next;
				}
				if (slice_index == -1){	// When there is no valid slice.
					printf("Mapping information for block[%d] is wrong.\n", block_index);
					if (fp != NULL)
						fclose(fp);
					return RET_LOGIC_ERROR;
				}

				// Read one slice from a file.
				tail_gap = tail_offset - slice_list[slice_index].tail_offset;	// This tail slice may start before tail_offset.
				//printf("tail_gap for slice[%I64d] = %zu.\n", slice_index, tail_gap);
				file_index = slice_list[slice_index].file;
				file_offset = slice_list[slice_index].offset + tail_gap;
				read_size = slice_list[slice_index].size - tail_gap;
				if ( (fp == NULL) || (file_index != file_prev) ){
					if (fp != NULL){	// Close previous input file.
						fclose(fp);
						fp = NULL;
					}
					fp = fopen(file_list[file_index].name, "rb");
					if (fp == NULL){
						perror("Failed to open Input File");
						return RET_FILE_IO_ERROR;
					}
					file_prev = file_index;
				}
				if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
					perror("Failed to seek Input File");
					fclose(fp);
					return RET_FILE_IO_ERROR;
				}
				if (fread(work_buf + tail_offset, 1, read_size, fp) != read_size){
					perror("Failed to read tail slice on Input File");
					fclose(fp);
					return RET_FILE_IO_ERROR;
				}
				tail_offset += read_size;
			}
		}
		// Zero fill rest bytes
		memset(work_buf + data_size, 0, region_size - data_size);

		// At creating time, CRC of a block was set, even when the block includes multiple chunk tails.
		// It appends chunk tails as tail packing, and calculates their total CRC for the block.
		// But, after verification, a block without full size data doesn't have valid CRC value.
		if (block_list[block_index].state & 64){
			// Calculate checksum of block to confirm that input file was not changed.
			if (crc64(work_buf, data_size, 0) != block_list[block_index].crc){
				printf("Checksum of block[%d] is different.\n", block_index);
				fclose(fp);
				return RET_LOGIC_ERROR;
			}
		}

		// Calculate parity bytes in the region
		if (gf_size == 2){
			gf16_region_create_parity(galois_poly, work_buf, region_size);
		} else if (gf_size == 1){
			gf8_region_create_parity(galois_poly, work_buf, region_size);
		} else {
			region_create_parity(work_buf, region_size);
		}

		// Multipy one input block for all recovery blocks.
		rs_create_one_all(par3_ctx, block_index);

		// Print progress percent
		if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
			time_now = time(NULL);
			if (time_now != time_old){
				time_old = time_now;
				// Because block_count is 16-bit value, "int" (32-bit signed integer) is enough.
				progress_now = (block_index * 1000) / block_count;
				if (progress_now != progress_old){
					progress_old = progress_now;
					printf("%d.%d%%\r", progress_now / 10, progress_now % 10);	// 0.0% ~ 100.0%
				}
			}
		}
	}
	if (fp != NULL){
		if (fclose(fp) != 0){
			perror("Failed to close Input File");
			return RET_FILE_IO_ERROR;
		}
	}

	// Release allocated memory
	free(work_buf);
	par3_ctx->work_buf = NULL;

	if (par3_ctx->noise_level >= 0){
		clock_now = clock() - clock_now;
		printf("done in %.1f seconds.\n", (double)clock_now / CLOCKS_PER_SEC);
		printf("\n");
	}

	return 0;
}

// This keeps all input blocks and recovery blocks partially by spliting every block.
// GF tables and recovery blocks were allocated already.
int create_recovery_block_split(PAR3_CTX *par3_ctx)
{
	char *name_prev, *file_name;
	uint8_t *block_data, *buf_p;
	uint8_t gf_size;
	int ret, galois_poly;
	int progress_old, progress_now;
	uint32_t split_count;
	uint32_t file_index, file_prev;
	size_t io_size;
	int64_t slice_index, file_offset;
	uint64_t crc, block_index;
	uint64_t block_size, block_count;
	uint64_t recovery_block_count, first_recovery_block, max_recovery_block;
	uint64_t alloc_size, region_size, split_size;
	uint64_t data_size, part_size, split_offset;
	uint64_t tail_offset, tail_gap;
	uint64_t progress_total, progress_step;
	PAR3_FILE_CTX *file_list;
	PAR3_SLICE_CTX *slice_list;
	PAR3_BLOCK_CTX *block_list;
	PAR3_POS_CTX *position_list;
	FILE *fp;
	time_t time_old, time_now;
	clock_t clock_now;

	// For Leopard-RS library
	uint32_t work_count;
	uint8_t **original_data = NULL, **work_data = NULL;

	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	recovery_block_count = par3_ctx->recovery_block_count;
	first_recovery_block = par3_ctx->first_recovery_block;
	max_recovery_block = par3_ctx->max_recovery_block;
	gf_size = par3_ctx->gf_size;
	galois_poly = par3_ctx->galois_poly;
	file_list = par3_ctx->input_file_list;
	slice_list = par3_ctx->slice_list;
	block_list = par3_ctx->block_list;
	position_list = par3_ctx->position_list;

	if (recovery_block_count == 0)
		return RET_LOGIC_ERROR;

	// Set required memory size at first
	if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
		ret = leo_init();	// Initialize Leopard-RS library.
		if (ret != 0){
			printf("Failed to initialize Leopard-RS library (%d)\n", ret);
			return RET_LOGIC_ERROR;
		}
		work_count = leo_encode_work_count((uint32_t)block_count, (uint32_t)max_recovery_block);
		// max_recovery_block is equal or larger than (first_recovery_block + recovery_block_count).
		//printf("Leopard-RS: work_count = %u\n", work_count);
		// Leopard-RS requires multiple of 64 bytes for SIMD.
		region_size = (block_size + 4 + 63) & ~63;
		alloc_size = region_size * (block_count + work_count);

	} else {	// Reed-Solomon Erasure Codes
		// Mmeory alignment is 4 bytes.
		region_size = (block_size + 4 + 3) & ~3;
		alloc_size = region_size * (block_count + recovery_block_count);
	}

	// for test split
	//par3_ctx->memory_limit = (alloc_size + 1) / 2;
	//par3_ctx->memory_limit = (alloc_size + 2) / 3;

	// Limited memory usage
	if ( (par3_ctx->memory_limit > 0) && (alloc_size > par3_ctx->memory_limit) ){
		split_count = (uint32_t)((alloc_size + par3_ctx->memory_limit - 1) / par3_ctx->memory_limit);
		split_size = (block_size + split_count - 1) / split_count;	// This is splitted block size to fit in limited memory.
		if (gf_size == 2){
			// aligned to 2 bytes for 16-bit Galois Field
			split_size = (split_size + 1) & ~1;
		}
		if (split_size > block_size)
			split_size = block_size;
		split_count = (uint32_t)((block_size + split_size - 1) / split_size);
		if (par3_ctx->noise_level >= 1){
			printf("\nSplit block to %u pieces of %I64u bytes.\n", split_count, split_size);
		}
	} else {
		split_count = 1;
		split_size = block_size;
	}

	// Allocate memory to keep all splitted blocks.
	if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
		// Leopard-RS requires alignment of 64 bytes.
		region_size = (split_size + 4 + 63) & ~63;
		alloc_size = region_size * (block_count + work_count);	// work_count is larger than recovery_block_count.
		// Though Leopard-RS doesn't require memory alignment for SIMD, align to 32 bytes may be faster.
		if (par3_ctx->noise_level >= 2){
			printf("\nAligned size of block data = %I64u\n", region_size);
			printf("Allocated memory size = %I64u * (%I64u + %u) = %I64u\n", region_size, block_count, work_count, alloc_size);
		}
	} else {	// Reed-Solomon Erasure Codes
		region_size = (split_size + 4 + 3) & ~3;
		alloc_size = region_size * (block_count + recovery_block_count);
		if (par3_ctx->noise_level >= 2){
			printf("\nAligned size of block data = %I64u\n", region_size);
			printf("Allocated memory size = %I64u * (%I64u + %I64u) = %I64u\n", region_size, block_count, recovery_block_count, alloc_size);
		}
	}
	block_data = malloc(alloc_size);
	if (block_data == NULL){
		perror("Failed to allocate memory for block data");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->block_data = block_data;

	if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
		// List of pointer
		original_data = malloc(sizeof(block_data) * (block_count + work_count));
		if (original_data == NULL){
			perror("Failed to allocate memory for Leopard-RS");
			return RET_MEMORY_ERROR;
		}
		buf_p = block_data;
		for (block_index = 0; block_index < block_count; block_index++){
			original_data[block_index] = buf_p;
			buf_p += region_size;
		}
		work_data = original_data + block_count;
		// Change order of recovery data to skip until first_recovery_block.
		for (block_index = first_recovery_block; block_index < first_recovery_block + recovery_block_count; block_index++){
			work_data[block_index] = buf_p;
			buf_p += region_size;
		}
		for (block_index = 0; block_index < first_recovery_block; block_index++){
			work_data[block_index] = buf_p;
			buf_p += region_size;
		}
		for (block_index = first_recovery_block + recovery_block_count; block_index < work_count; block_index++){
			work_data[block_index] = buf_p;
			buf_p += region_size;
		}
		par3_ctx->matrix = original_data;	// Release this later
	}

	if (par3_ctx->noise_level >= 0){
		printf("\nComputing recovery blocks:\n");
		progress_total = (block_count * recovery_block_count + block_count + recovery_block_count) * split_count;
		progress_step = 0;
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}

	// This file access style would support all Error Correction Codes.
	name_prev = NULL;
	fp = NULL;
	for (split_offset = 0; split_offset < block_size; split_offset += split_size){
		buf_p = block_data;	// Starting position of input blocks
		file_prev = 0xFFFFFFFF;

		// Read all input blocks on memory
		for (block_index = 0; block_index < block_count; block_index++){
			// Read each input block from input files.
			data_size = block_list[block_index].size;
			part_size = data_size - split_offset;
			if (part_size > split_size)
				part_size = split_size;

			if (block_list[block_index].state & 1){	// including full size data
				slice_index = block_list[block_index].slice;
				while (slice_index != -1){
					if (slice_list[slice_index].size == block_size)
						break;
					slice_index = slice_list[slice_index].next;
				}
				if (slice_index == -1){	// When there is no valid slice.
					printf("Mapping information for block[%I64u] is wrong.\n", block_index);
					if (fp != NULL)
						fclose(fp);
					return RET_LOGIC_ERROR;
				}

				// Read a part of slice from a file.
				file_index = slice_list[slice_index].file;
				file_offset = slice_list[slice_index].offset + split_offset;
				io_size = part_size;
				if (par3_ctx->noise_level >= 3){
					printf("Reading %zu bytes of slice[%I64d] for input block[%I64u]\n", io_size, slice_index, block_index);
				}
				if ( (fp == NULL) || (file_index != file_prev) ){
					if (fp != NULL){	// Close previous input file.
						fclose(fp);
						fp = NULL;
					}
					fp = fopen(file_list[file_index].name, "rb");
					if (fp == NULL){
						perror("Failed to open Input File");
						return RET_FILE_IO_ERROR;
					}
					file_prev = file_index;
				}
				if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
					perror("Failed to seek Input File");
					fclose(fp);
					return RET_FILE_IO_ERROR;
				}
				if (fread(buf_p, 1, io_size, fp) != io_size){
					perror("Failed to read slice on Input File");
					fclose(fp);
					return RET_FILE_IO_ERROR;
				}

			} else if (data_size > split_offset){	// tail data only (one tail or packed tails)
				if (par3_ctx->noise_level >= 3){
					printf("Reading %I64u bytes for input block[%I64u]\n", part_size, block_index);
				}
				tail_offset = split_offset;
				while (tail_offset < split_offset + part_size){	// Read tails until data end.
					slice_index = block_list[block_index].slice;
					while (slice_index != -1){
						//printf("block = %I64u, size = %zu, offset = %zu, slice = %I64d\n", block_index, data_size, tail_offset, slice_index);
						// Even when chunk tails are overlaped, it will find tail slice of next position.
						if ( (slice_list[slice_index].tail_offset + slice_list[slice_index].size > tail_offset)
								&& (slice_list[slice_index].tail_offset <= tail_offset) ){
							break;
						}
						slice_index = slice_list[slice_index].next;
					}
					if (slice_index == -1){	// When there is no valid slice.
						printf("Mapping information for block[%I64u] is wrong.\n", block_index);
						if (fp != NULL)
							fclose(fp);
						return RET_LOGIC_ERROR;
					}

					// Read one slice from a file.
					tail_gap = tail_offset - slice_list[slice_index].tail_offset;	// This tail slice may start before tail_offset.
					//printf("tail_gap for slice[%I64d] = %zu.\n", slice_index, tail_gap);
					file_index = slice_list[slice_index].file;
					file_offset = slice_list[slice_index].offset + tail_gap;
					io_size = slice_list[slice_index].size - tail_gap;
					if ( (fp == NULL) || (file_index != file_prev) ){
						if (fp != NULL){	// Close previous input file.
							fclose(fp);
							fp = NULL;
						}
						fp = fopen(file_list[file_index].name, "rb");
						if (fp == NULL){
							perror("Failed to open Input File");
							return RET_FILE_IO_ERROR;
						}
						file_prev = file_index;
					}
					if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
						perror("Failed to seek Input File");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
					if (fread(buf_p + tail_offset - split_offset, 1, io_size, fp) != io_size){
						perror("Failed to read tail slice on Input File");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
					tail_offset += io_size;
				}

			} else {	// Zero fill partial input block
				memset(buf_p, 0, region_size);
			}

			// Calculate checksum of block to confirm that input file was not changed.
			if (split_offset == 0){
				crc = 0;
			} else {
				memcpy(&crc, block_list[block_index].hash, 8);	// Use previous CRC value
			}
			if (data_size > split_offset){	// When there is slice data to process.
				memset(buf_p + part_size, 0, region_size - part_size);	// Zero fill rest bytes
				crc = crc64(buf_p, part_size, crc);

				// Calculate parity bytes in the region
				if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
					if (gf_size == 2){
						leo_region_create_parity(buf_p, region_size);
					} else {
						region_create_parity(buf_p, region_size);
					}
				} else {
					if (gf_size == 2){
						gf16_region_create_parity(galois_poly, buf_p, region_size);
					} else if (gf_size == 1){
						gf8_region_create_parity(galois_poly, buf_p, region_size);
					} else {
						region_create_parity(buf_p, region_size);
					}
				}
			}
			// Intermediate CRC value is stored in "block_list[block_index].hash".
			if (block_list[block_index].state & 64){
				if (split_offset + split_size >= block_size){	// At the last
					if (crc != block_list[block_index].crc){
						printf("Checksum of block[%I64u] is different.\n", block_index);
						fclose(fp);
						return RET_LOGIC_ERROR;
					}
				} else {
					memcpy(block_list[block_index].hash, &crc, 8);	// Save this CRC value
				}
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
				progress_step++;
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

			buf_p += region_size;	// Goto next partial block
		}
		if (fp != NULL){
			if (fclose(fp) != 0){
				perror("Failed to close Input File");
				return RET_FILE_IO_ERROR;
			}
			fp = NULL;
		}

		// Create all recovery blocks on memory
		if (par3_ctx->ecc_method & 1){	// Cauchy Reed-Solomon Codes
			rs_create_all(par3_ctx, region_size, progress_total, progress_step);

		} else if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
			ret = leo_encode(region_size, (uint32_t)block_count, (uint32_t)max_recovery_block, work_count, original_data, work_data);
			if (ret != 0){
				printf("Failed to call Leopard-RS library (%d)\n", ret);
				return RET_LOGIC_ERROR;
			}

		}
		if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
			progress_step += block_count * recovery_block_count;
			time_old = time(NULL);
		}

		// Write all recovery blocks on recovery files
		part_size = block_size - split_offset;
		if (part_size > split_size)
			part_size = split_size;
		io_size = part_size;
		buf_p = block_data + region_size * block_count;	// Starting position of recovery blocks
		for (block_index = 0; block_index < recovery_block_count; block_index++){
			// Check parity of recovery block to confirm that calculation was correct.
			if (par3_ctx->ecc_method & 8){
				if (gf_size == 2){
					ret = leo_region_check_parity(buf_p, region_size);
				} else {
					ret = region_check_parity(buf_p, region_size);
				}
			} else {
				if (gf_size == 2){
					ret = gf16_region_check_parity(galois_poly, buf_p, region_size);
				} else if (gf_size == 1){
					ret = gf8_region_check_parity(galois_poly, buf_p, region_size);
				} else {
					ret = region_check_parity(buf_p, region_size);
				}
			}
			if (ret != 0){
				printf("Parity of recovery block[%I64u] is different.\n", block_index);
				if (fp != NULL)
					fclose(fp);
				return RET_LOGIC_ERROR;
			}

			// Position of Recovery Data Packet in recovery file
			file_name = position_list[block_index].name;
			file_offset = position_list[block_index].offset + 88 + split_offset;

			// Calculate CRC of packet data to check error later.
			position_list[block_index].crc = crc64(buf_p, part_size, position_list[block_index].crc);

			// Write partial recovery block
			if ( (fp == NULL) || (file_name != name_prev) ){
				if (fp != NULL){	// Close previous recovery file.
					fclose(fp);
					fp = NULL;
				}
				fp = fopen(file_name, "r+b");	// Over-write on existing file
				if (fp == NULL){
					perror("Failed to open Recovery File");
					return RET_FILE_IO_ERROR;
				}
				name_prev = file_name;
			}
			if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
				perror("Failed to seek Recovery File");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			if (fwrite(buf_p, 1, part_size, fp) != part_size){
				perror("Failed to write Recovery Block on Recovery File");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
				progress_step++;
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

			buf_p += region_size;
		}
	}

/*
{	// for debug
FILE *fp2;
buf_p = block_data + region_size * block_count;	// Starting position of recovery blocks

fp2 = fopen("test.bin", "wb");
fwrite(buf_p, 1, region_size * recovery_block_count, fp2);
fclose(fp2);
}
*/

	free(block_data);
	par3_ctx->block_data = NULL;

	// Allocate memory to read one Recovery Data Packet.
	alloc_size = 80 + block_size;
	buf_p = malloc(alloc_size);
	if (buf_p == NULL){
		perror("Failed to allocate memory for Recovery Data Packet");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->work_buf = buf_p;

	// Calculate checksum of every Recovery Data Packet
	io_size = 64 + block_size;	// packet header after checksum and packet body
	for (block_index = 0; block_index < recovery_block_count; block_index++){
		// Position of Recovery Data Packet in recovery file
		file_name = position_list[block_index].name;
		file_offset = position_list[block_index].offset + 8;	// Offset of checksum

		// Read packet data and write checksum
		if ( (fp == NULL) || (file_name != name_prev) ){
			if (fp != NULL){	// Close previous recovery file.
				fclose(fp);
				fp = NULL;
			}
			fp = fopen(file_name, "r+b");	// Over-write on existing file
			if (fp == NULL){
				perror("Failed to open Recovery File");
				return RET_FILE_IO_ERROR;
			}
			name_prev = file_name;
		}
		if (_fseeki64(fp, file_offset + 16, SEEK_SET) != 0){
			perror("Failed to seek Recovery File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fread(buf_p + 16, 1, io_size, fp) != io_size){
			perror("Failed to read Recovery Data Packet");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}

		// Compare CRC of written packet data to confirm integrity.
		crc = crc64(buf_p + 16, io_size, 0);
		if (crc != position_list[block_index].crc){
			printf("Packet data of recovery block[%I64u] is different.\n", block_index);
			fclose(fp);
			return RET_LOGIC_ERROR;
		}

		// Calculate checksum of this packet
		blake3(buf_p + 16, io_size, buf_p);

		// Write checksum
		if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
			perror("Failed to seek Recovery File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fwrite(buf_p, 1, 16, fp) != 16){
			perror("Failed to write checksum of Recovery Data Packet");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}
	if (fclose(fp) != 0){
		perror("Failed to close Recovery File");
		return RET_FILE_IO_ERROR;
	}

	if (par3_ctx->noise_level >= 0){
		if (par3_ctx->noise_level <= 2){
			if (progress_step < progress_total)
				printf("Didn't finish progress. %I64u / %I64u\n", progress_step, progress_total);
		}
		clock_now = clock() - clock_now;
		printf("done in %.1f seconds.\n", (double)clock_now / CLOCKS_PER_SEC);
		printf("\n");
	}

	// Release some allocated memory
	free(buf_p);
	par3_ctx->work_buf = NULL;
	free(position_list);
	par3_ctx->position_list = NULL;
	if (par3_ctx->matrix){
		free(par3_ctx->matrix);
		par3_ctx->matrix = NULL;
	}

	return 0;
}

// At this time, interleaving is adapted only for FFT based Reed-Solomon Codes.
// When there are multiple cohorts, it calculates recovery blocks in each cohort.
// This keeps one cohort's all input blocks and recovery blocks partially by spliting every block.
// GF tables and recovery blocks were allocated already.
int create_recovery_block_cohort(PAR3_CTX *par3_ctx)
{
	char *name_prev, *file_name;
	uint8_t *block_data, *buf_p;
	uint8_t gf_size;
	int ret, galois_poly;
	int progress_old, progress_now;
	uint32_t split_count;
	uint32_t file_index, file_prev;
	uint32_t cohort_count, cohort_index;
	size_t io_size;
	int64_t slice_index, file_offset;
	uint64_t crc, block_index;
	uint64_t block_size, block_count, recovery_block_count;
	uint64_t block_count2, recovery_block_count2, first_recovery_block2, max_recovery_block2;
	uint64_t alloc_size, region_size, split_size;
	uint64_t data_size, part_size, split_offset;
	uint64_t tail_offset, tail_gap;
	uint64_t progress_total, progress_step;
	PAR3_FILE_CTX *file_list;
	PAR3_SLICE_CTX *slice_list;
	PAR3_BLOCK_CTX *block_list;
	PAR3_POS_CTX *position_list;
	FILE *fp;
	time_t time_old, time_now;
	clock_t clock_now;

	// For Leopard-RS library
	uint32_t work_count;
	uint8_t **original_data = NULL, **work_data = NULL;

	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	recovery_block_count = par3_ctx->recovery_block_count;
	gf_size = par3_ctx->gf_size;
	galois_poly = par3_ctx->galois_poly;
	file_list = par3_ctx->input_file_list;
	slice_list = par3_ctx->slice_list;
	block_list = par3_ctx->block_list;
	position_list = par3_ctx->position_list;

	if (recovery_block_count == 0)
		return RET_LOGIC_ERROR;

	// Set count for each cohort
	cohort_count = (uint32_t)(par3_ctx->interleave) + 1;	// Minimum value is 2.
	block_count2 = (block_count + cohort_count - 1) / cohort_count;	// round up
	recovery_block_count2 = recovery_block_count / cohort_count;
	first_recovery_block2 = par3_ctx->first_recovery_block / cohort_count;
	max_recovery_block2 = par3_ctx->max_recovery_block / cohort_count;
	// max_recovery_block2 is equal or larger than (first_recovery_block2 + recovery_block_count2).
	//printf("cohort_count = %u, block_count2 = %I64u\n", cohort_count, block_count2);
	//printf("recovery_block_count2 = %I64u, first_recovery_block2 = %I64u\n", recovery_block_count2, first_recovery_block2);
	//printf("max_recovery_block2 = %I64u\n", max_recovery_block2);

	// Set required memory size at first
	ret = leo_init();	// Initialize Leopard-RS library.
	if (ret != 0){
		printf("Failed to initialize Leopard-RS library (%d)\n", ret);
		return RET_LOGIC_ERROR;
	}
	work_count = leo_encode_work_count((uint32_t)block_count2, (uint32_t)max_recovery_block2);
	//printf("Leopard-RS: work_count = %u\n", work_count);
	// Leopard-RS requires multiple of 64 bytes for SIMD.
	region_size = (block_size + 4 + 63) & ~63;
	alloc_size = region_size * (block_count2 + work_count);

	// for test split
	//par3_ctx->memory_limit = (alloc_size + 1) / 2;
	//par3_ctx->memory_limit = (alloc_size + 2) / 3;

	// Limited memory usage
	if ( (par3_ctx->memory_limit > 0) && (alloc_size > par3_ctx->memory_limit) ){
		split_count = (uint32_t)((alloc_size + par3_ctx->memory_limit - 1) / par3_ctx->memory_limit);
		split_size = (block_size + split_count - 1) / split_count;	// This is splitted block size to fit in limited memory.
		if (gf_size == 2){
			// aligned to 2 bytes for 16-bit Galois Field
			split_size = (split_size + 1) & ~1;
		}
		if (split_size > block_size)
			split_size = block_size;
		split_count = (uint32_t)((block_size + split_size - 1) / split_size);
		if (par3_ctx->noise_level >= 1){
			printf("\nSplit block to %u pieces of %I64u bytes.\n", split_count, split_size);
		}
	} else {
		split_count = 1;
		split_size = block_size;
	}

	// Allocate memory to keep all splitted blocks.
	// Leopard-RS requires alignment of 64 bytes.
	region_size = (split_size + 4 + 63) & ~63;
	alloc_size = region_size * (block_count2 + work_count);	// work_count is larger than recovery_block_count.
	// Though Leopard-RS doesn't require memory alignment for SIMD, align to 32 bytes may be faster.
	if (par3_ctx->noise_level >= 2){
		printf("\nAligned size of block data = %I64u\n", region_size);
		printf("Allocated memory size = %I64u * (%I64u + %u) = %I64u\n", region_size, block_count2, work_count, alloc_size);
	}
	block_data = malloc(alloc_size);
	if (block_data == NULL){
		perror("Failed to allocate memory for block data");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->block_data = block_data;

	// List of pointer
	original_data = malloc(sizeof(block_data) * (block_count2 + work_count));
	if (original_data == NULL){
		perror("Failed to allocate memory for Leopard-RS");
		return RET_MEMORY_ERROR;
	}
	buf_p = block_data;
	for (block_index = 0; block_index < block_count2; block_index++){
		original_data[block_index] = buf_p;
		buf_p += region_size;
	}
	work_data = original_data + block_count2;
	// Change order of recovery data to skip until first_recovery_block.
	for (block_index = first_recovery_block2; block_index < first_recovery_block2 + recovery_block_count2; block_index++){
		work_data[block_index] = buf_p;
		buf_p += region_size;
	}
	for (block_index = 0; block_index < first_recovery_block2; block_index++){
		work_data[block_index] = buf_p;
		buf_p += region_size;
	}
	for (block_index = first_recovery_block2 + recovery_block_count2; block_index < work_count; block_index++){
		work_data[block_index] = buf_p;
		buf_p += region_size;
	}
	par3_ctx->matrix = original_data;	// Release this later

	if (par3_ctx->noise_level >= 0){
		printf("\nComputing recovery blocks:\n");
		progress_total = (block_count2 * recovery_block_count + block_count + recovery_block_count) * split_count;
		progress_step = 0;
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}

	name_prev = NULL;
	fp = NULL;
	// Process each cohort
	for (cohort_index = 0; cohort_index < cohort_count; cohort_index++){
		if ( (cohort_count < 10) && (par3_ctx->noise_level >= 1) ){
			split_count = 0;
			split_offset = block_count % cohort_count;
			if ( (split_offset > 0) && (cohort_index >= split_offset) )
				split_count++;
			printf("cohort[%u] : dummy = %u, recovery = %I64u\n", cohort_index, split_count, recovery_block_count2);
		}
		for (split_offset = 0; split_offset < block_size; split_offset += split_size){
			//printf("cohort_index = %u, split_offset = %I64u\n", cohort_index, split_offset);
			buf_p = block_data;	// Starting position of input blocks
			file_prev = 0xFFFFFFFF;

			// Read all input blocks belong to the cohort on memory
			for (block_index = cohort_index; block_index < block_count; block_index += cohort_count){
				// Read each input block from input files.
				data_size = block_list[block_index].size;
				part_size = data_size - split_offset;
				if (part_size > split_size)
					part_size = split_size;

				if (block_list[block_index].state & 1){	// including full size data
					slice_index = block_list[block_index].slice;
					while (slice_index != -1){
						if (slice_list[slice_index].size == block_size)
							break;
						slice_index = slice_list[slice_index].next;
					}
					if (slice_index == -1){	// When there is no valid slice.
						printf("Mapping information for block[%I64u] is wrong.\n", block_index);
						if (fp != NULL)
							fclose(fp);
						return RET_LOGIC_ERROR;
					}

					// Read a part of slice from a file.
					file_index = slice_list[slice_index].file;
					file_offset = slice_list[slice_index].offset + split_offset;
					io_size = part_size;
					if (par3_ctx->noise_level >= 3){
						printf("Reading %zu bytes of slice[%I64d] for input block[%I64u]\n", io_size, slice_index, block_index);
					}
					if ( (fp == NULL) || (file_index != file_prev) ){
						if (fp != NULL){	// Close previous input file.
							fclose(fp);
							fp = NULL;
						}
						fp = fopen(file_list[file_index].name, "rb");
						if (fp == NULL){
							perror("Failed to open Input File");
							return RET_FILE_IO_ERROR;
						}
						file_prev = file_index;
					}
					if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
						perror("Failed to seek Input File");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
					if (fread(buf_p, 1, io_size, fp) != io_size){
						perror("Failed to read slice on Input File");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}

				} else if (data_size > split_offset){	// tail data only (one tail or packed tails)
					if (par3_ctx->noise_level >= 3){
						printf("Reading %I64u bytes for input block[%I64u]\n", part_size, block_index);
					}
					tail_offset = split_offset;
					while (tail_offset < split_offset + part_size){	// Read tails until data end.
						slice_index = block_list[block_index].slice;
						while (slice_index != -1){
							//printf("block = %I64u, size = %zu, offset = %zu, slice = %I64d\n", block_index, data_size, tail_offset, slice_index);
							// Even when chunk tails are overlaped, it will find tail slice of next position.
							if ( (slice_list[slice_index].tail_offset + slice_list[slice_index].size > tail_offset)
									&& (slice_list[slice_index].tail_offset <= tail_offset) ){
								break;
							}
							slice_index = slice_list[slice_index].next;
						}
						if (slice_index == -1){	// When there is no valid slice.
							printf("Mapping information for block[%I64u] is wrong.\n", block_index);
							if (fp != NULL)
								fclose(fp);
							return RET_LOGIC_ERROR;
						}

						// Read one slice from a file.
						tail_gap = tail_offset - slice_list[slice_index].tail_offset;	// This tail slice may start before tail_offset.
						//printf("tail_gap for slice[%I64d] = %zu.\n", slice_index, tail_gap);
						file_index = slice_list[slice_index].file;
						file_offset = slice_list[slice_index].offset + tail_gap;
						io_size = slice_list[slice_index].size - tail_gap;
						if ( (fp == NULL) || (file_index != file_prev) ){
							if (fp != NULL){	// Close previous input file.
								fclose(fp);
								fp = NULL;
							}
							fp = fopen(file_list[file_index].name, "rb");
							if (fp == NULL){
								perror("Failed to open Input File");
								return RET_FILE_IO_ERROR;
							}
							file_prev = file_index;
						}
						if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
							perror("Failed to seek Input File");
							fclose(fp);
							return RET_FILE_IO_ERROR;
						}
						if (fread(buf_p + tail_offset - split_offset, 1, io_size, fp) != io_size){
							perror("Failed to read tail slice on Input File");
							fclose(fp);
							return RET_FILE_IO_ERROR;
						}
						tail_offset += io_size;
					}

				} else {	// Zero fill partial input block
					memset(buf_p, 0, region_size);
				}

				// Calculate checksum of block to confirm that input file was not changed.
				if (split_offset == 0){
					crc = 0;
				} else {
					memcpy(&crc, block_list[block_index].hash, 8);	// Use previous CRC value
				}
				if (data_size > split_offset){	// When there is slice data to process.
					memset(buf_p + part_size, 0, region_size - part_size);	// Zero fill rest bytes
					crc = crc64(buf_p, part_size, crc);

					// Calculate parity bytes in the region
					if (gf_size == 2){
						leo_region_create_parity(buf_p, region_size);
					} else {
						region_create_parity(buf_p, region_size);
					}
				}
				if (block_list[block_index].state & 64){
					if (split_offset + split_size >= block_size){	// At the last
						if (crc != block_list[block_index].crc){
							printf("Checksum of block[%I64u] is different.\n", block_index);
							fclose(fp);
							return RET_LOGIC_ERROR;
						}
					} else {
						memcpy(block_list[block_index].hash, &crc, 8);	// Save this CRC value
					}
				}

				// Print progress percent
				if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
					progress_step++;
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

				buf_p += region_size;	// Goto next partial block
			}
			if (fp != NULL){
				if (fclose(fp) != 0){
					perror("Failed to close Input File");
					return RET_FILE_IO_ERROR;
				}
				fp = NULL;
			}

			// When the last input block doesn't exist in this cohort, zero fill it.
			if (block_index < block_count2 * cohort_count){
				//printf("zero fill %I64u, block_count2 * cohort_count = %I64u\n", block_index, block_count2 * cohort_count);
				memset(buf_p, 0, region_size);
			}

			// Create all recovery blocks on memory
			ret = leo_encode(region_size, (uint32_t)block_count2, (uint32_t)max_recovery_block2, work_count, original_data, work_data);
			if (ret != 0){
				printf("Failed to call Leopard-RS library (%d)\n", ret);
				return RET_LOGIC_ERROR;
			}

			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
				progress_step += block_count2 * recovery_block_count2;
				time_old = time(NULL);
			}

			// Write all recovery blocks on recovery files
			part_size = block_size - split_offset;
			if (part_size > split_size)
				part_size = split_size;
			io_size = part_size;
			buf_p = block_data + region_size * block_count2;	// Starting position of recovery blocks
			for (block_index = cohort_index; block_index < recovery_block_count; block_index += cohort_count){
				// Check parity of recovery block to confirm that calculation was correct.
				if (gf_size == 2){
					ret = leo_region_check_parity(buf_p, region_size);
				} else {
					ret = region_check_parity(buf_p, region_size);
				}
				if (ret != 0){
					printf("Parity of recovery block[%I64u] is different.\n", block_index);
					if (fp != NULL)
						fclose(fp);
					return RET_LOGIC_ERROR;
				}

				// Position of Recovery Data Packet in recovery file
				file_name = position_list[block_index].name;
				file_offset = position_list[block_index].offset + 88 + split_offset;

				// Calculate CRC of packet data to check error later.
				position_list[block_index].crc = crc64(buf_p, part_size, position_list[block_index].crc);

				// Write partial recovery block
				if ( (fp == NULL) || (file_name != name_prev) ){
					if (fp != NULL){	// Close previous recovery file.
						fclose(fp);
						fp = NULL;
					}
					fp = fopen(file_name, "r+b");	// Over-write on existing file
					if (fp == NULL){
						perror("Failed to open Recovery File");
						return RET_FILE_IO_ERROR;
					}
					name_prev = file_name;
				}
				if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
					perror("Failed to seek Recovery File");
					fclose(fp);
					return RET_FILE_IO_ERROR;
				}
				if (fwrite(buf_p, 1, part_size, fp) != part_size){
					perror("Failed to write Recovery Block on Recovery File");
					fclose(fp);
					return RET_FILE_IO_ERROR;
				}

				// Print progress percent
				if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
					progress_step++;
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

				buf_p += region_size;
			}
		}
	}
/*
{	// for debug
FILE *fp2;
buf_p = block_data + region_size * block_count2;	// Starting position of recovery blocks

fp2 = fopen("test.bin", "wb");
fwrite(buf_p, 1, region_size * recovery_block_count2, fp2);
fclose(fp2);
}
*/

	free(block_data);
	par3_ctx->block_data = NULL;

	// Allocate memory to read one Recovery Data Packet.
	alloc_size = 80 + block_size;
	buf_p = malloc(alloc_size);
	if (buf_p == NULL){
		perror("Failed to allocate memory for Recovery Data Packet");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->work_buf = buf_p;

	// Calculate checksum of every Recovery Data Packet
	io_size = 64 + block_size;	// packet header after checksum and packet body
	for (block_index = 0; block_index < recovery_block_count; block_index++){
		// Position of Recovery Data Packet in recovery file
		file_name = position_list[block_index].name;
		file_offset = position_list[block_index].offset + 8;	// Offset of checksum

		// Read packet data and write checksum
		if ( (fp == NULL) || (file_name != name_prev) ){
			if (fp != NULL){	// Close previous recovery file.
				fclose(fp);
				fp = NULL;
			}
			fp = fopen(file_name, "r+b");	// Over-write on existing file
			if (fp == NULL){
				perror("Failed to open Recovery File");
				return RET_FILE_IO_ERROR;
			}
			name_prev = file_name;
		}
		if (_fseeki64(fp, file_offset + 16, SEEK_SET) != 0){
			perror("Failed to seek Recovery File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fread(buf_p + 16, 1, io_size, fp) != io_size){
			perror("Failed to read Recovery Data Packet");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}

		// Compare CRC of written packet data to confirm integrity.
		crc = crc64(buf_p + 16, io_size, 0);
		if (crc != position_list[block_index].crc){
			printf("Packet data of recovery block[%I64u] is different.\n", block_index);
			fclose(fp);
			return RET_LOGIC_ERROR;
		}

		// Calculate checksum of this packet
		blake3(buf_p + 16, io_size, buf_p);

		// Write checksum
		if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
			perror("Failed to seek Recovery File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fwrite(buf_p, 1, 16, fp) != 16){
			perror("Failed to write checksum of Recovery Data Packet");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}
	if (fclose(fp) != 0){
		perror("Failed to close Recovery File");
		return RET_FILE_IO_ERROR;
	}

	if (par3_ctx->noise_level >= 0){
		if (par3_ctx->noise_level <= 2){
			if (progress_step < progress_total)
				printf("Didn't finish progress. %I64u / %I64u\n", progress_step, progress_total);
		}
		clock_now = clock() - clock_now;
		printf("done in %.1f seconds.\n", (double)clock_now / CLOCKS_PER_SEC);
		printf("\n");
	}

	// Release some allocated memory
	free(buf_p);
	par3_ctx->work_buf = NULL;
	free(position_list);
	par3_ctx->position_list = NULL;
	if (par3_ctx->matrix){
		free(par3_ctx->matrix);
		par3_ctx->matrix = NULL;
	}

	return 0;
}

