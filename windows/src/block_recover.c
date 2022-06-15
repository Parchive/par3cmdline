// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libpar3.h"
#include "galois.h"
#include "hash.h"
#include "reedsolomon.h"


/*
This keeps all lost input blocks on memory.

read every input blocks except lost blocks
 per each input block
  restore lost input slices
  recover (multiple & add to) lost input blocks

read every using recovery blocks
 per each recovery block
  recover (multiple & add to) lost input blocks

restore lost input blocks

write chunk tails
*/
int recover_lost_block(PAR3_CTX *par3_ctx, char *temp_path, int lost_count)
{
	void *gf_table, *matrix;
	char *name_prev, *file_name;
	uint8_t *work_buf, buf_tail[40];
	uint8_t *block_data;
	uint8_t gf_size;
	int galois_poly, *lost_id, *recv_id;
	int block_count, block_index;
	int lost_index, ret;
	int progress_old, progress_now, progress_step;
	uint32_t file_count, file_index, file_prev;
	uint32_t chunk_index, chunk_num;
	size_t slice_size;
	int64_t slice_index, file_offset;
	uint64_t block_size, region_size, data_size;
	uint64_t tail_offset, tail_gap;
	uint64_t packet_count, packet_index;
	uint64_t file_size, chunk_size;
	PAR3_BLOCK_CTX *block_list;
	PAR3_SLICE_CTX *slice_list;
	PAR3_CHUNK_CTX *chunk_list;
	PAR3_FILE_CTX *file_list;
	PAR3_PKT_CTX *packet_list;
	FILE *fp_read, *fp_write;
	time_t time_old, time_now;
	clock_t clock_now;

	//printf("\n ecc_method = 0x%x, lost_count = %d\n", par3_ctx->ecc_method, lost_count);

	file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	block_count = (int)(par3_ctx->block_count);
	gf_size = par3_ctx->gf_size;
	galois_poly = par3_ctx->galois_poly;
	gf_table = par3_ctx->galois_table;
	matrix = par3_ctx->matrix;
	lost_id = par3_ctx->id_list;
	recv_id = lost_id + lost_count;
	block_data = par3_ctx->block_data;
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;
	chunk_list = par3_ctx->chunk_list;
	file_list = par3_ctx->input_file_list;
	packet_list = par3_ctx->recv_packet_list;
	packet_count = par3_ctx->recv_packet_count;

	region_size = (block_size + 4 + 3) & ~3;

	// Zero fill lost blocks
	memset(block_data, 0, region_size * lost_count);

	// Allocate memory to read one input block
	work_buf = malloc(region_size);
	if (work_buf == NULL){
		perror("Failed to allocate memory for input data");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->work_buf = work_buf;

	// Base name of temporary file
	sprintf(temp_path, "par3_%02X%02X%02X%02X%02X%02X%02X%02X_",
			par3_ctx->set_id[0], par3_ctx->set_id[1], par3_ctx->set_id[2], par3_ctx->set_id[3],
			par3_ctx->set_id[4], par3_ctx->set_id[5], par3_ctx->set_id[6], par3_ctx->set_id[7]);

	if (par3_ctx->noise_level >= 0){
		printf("\nRecovering lost input blocks:\n");
		progress_step = 0;
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}

	// Read available input blocks
	name_prev = NULL;
	file_prev = 0xFFFFFFFF;
	fp_read = NULL;
	fp_write = NULL;
	for (block_index = 0; block_index < block_count; block_index++){
		data_size = block_list[block_index].size;

		// Read block data from found file.
		if (block_list[block_index].state & 4){	// Full size data is available.
			slice_index = block_list[block_index].slice;
			while (slice_index != -1){
				if (slice_list[slice_index].size == block_size)
					break;
				slice_index = slice_list[slice_index].next;
			}
			if (slice_index == -1){	// When there is no valid slice.
				printf("Mapping information for block[%d] is wrong.\n", block_index);
				if (fp_read != NULL)
					fclose(fp_read);
				if (fp_write != NULL)
					fclose(fp_write);
				return RET_LOGIC_ERROR;
			}

			// Read one slice from a found file.
			file_name = slice_list[slice_index].find_name;
			file_offset = slice_list[slice_index].find_offset;
			slice_size = slice_list[slice_index].size;
			if (par3_ctx->noise_level >= 2){
				printf("Reading %zu bytes of slice[%I64d] for input block[%d]\n", slice_size, slice_index, block_index);
			}
			if ( (fp_read == NULL) || (file_name != name_prev) ){
				if (fp_read != NULL){	// Close previous input file.
					fclose(fp_read);
					fp_read = NULL;
				}
				fp_read = fopen(file_name, "rb");
				if (fp_read == NULL){
					perror("Failed to open Input File");
					if (fp_write != NULL)
						fclose(fp_write);
					return RET_FILE_IO_ERROR;
				}
				name_prev = file_name;
			}
			if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
				perror("Failed to seek Input File");
				fclose(fp_read);
				if (fp_write != NULL)
					fclose(fp_write);
				return RET_FILE_IO_ERROR;
			}
			if (fread(work_buf, 1, slice_size, fp_read) != slice_size){
				perror("Failed to read full slice on Input File");
				fclose(fp_read);
				if (fp_write != NULL)
					fclose(fp_write);
				return RET_FILE_IO_ERROR;
			}

		} else if (block_list[block_index].state & 16){	// All tail data is available. (one tail or packed tails)
			if (par3_ctx->noise_level >= 2){
				printf("Reading %I64u bytes for input block[%d]\n", data_size, block_index);
			}
			tail_offset = 0;
			while (tail_offset < data_size){	// Read tails until data end.
				slice_index = block_list[block_index].slice;
				while (slice_index != -1){
					//printf("block = %d, size = %I64u, offset = %I64u, slice = %I64d\n", block_index, data_size, tail_offset, slice_index);
					// Even when chunk tails are overlaped, it will find tail slice of next position.
					if ( (slice_list[slice_index].tail_offset + slice_list[slice_index].size > tail_offset) &&
							(slice_list[slice_index].tail_offset <= tail_offset) ){
						break;
					}
					slice_index = slice_list[slice_index].next;
				}
				if (slice_index == -1){	// When there is no valid slice.
					printf("Mapping information for block[%d] is wrong.\n", block_index);
					if (fp_read != NULL)
						fclose(fp_read);
					if (fp_write != NULL)
						fclose(fp_write);
					return RET_LOGIC_ERROR;
				}

				// Read one slice from a file.
				tail_gap = tail_offset - slice_list[slice_index].tail_offset;	// This tail slice may start before tail_offset.
				file_name = slice_list[slice_index].find_name;
				file_offset = slice_list[slice_index].find_offset + tail_gap;
				slice_size = slice_list[slice_index].size - tail_gap;
				if ( (fp_read == NULL) || (file_name != name_prev) ){
					if (fp_read != NULL){	// Close previous input file.
						fclose(fp_read);
						fp_read = NULL;
					}
					fp_read = fopen(file_name, "rb");
					if (fp_read == NULL){
						perror("Failed to open Input File");
						if (fp_write != NULL)
							fclose(fp_write);
						return RET_FILE_IO_ERROR;
					}
					name_prev = file_name;
				}
				if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
					perror("Failed to seek Input File");
					fclose(fp_read);
					if (fp_write != NULL)
						fclose(fp_write);
					return RET_FILE_IO_ERROR;
				}
				if (fread(work_buf + tail_offset, 1, slice_size, fp_read) != slice_size){
					perror("Failed to read tail slice on Input File");
					fclose(fp_read);
					if (fp_write != NULL)
						fclose(fp_write);
					return RET_FILE_IO_ERROR;
				}
				tail_offset += slice_size;
			}

			// Zero fill rest bytes
			if (data_size < block_size)
				memset(work_buf + data_size, 0, block_size - data_size);

		} else {	// The input block was lost.
			data_size = 0;	// Mark of lost block
		}

		if (data_size > 0){	// The block data is available.

			// Restore lost input slices
			slice_index = block_list[block_index].slice;
			while (slice_index != -1){
				file_index = slice_list[slice_index].file;
				// If belong file is missing or damaged.
				if ( ((file_list[file_index].state & 3) != 0) && ((file_list[file_index].state & 4) == 0) ){
					// Write one lost slice on temporary file.
					slice_size = slice_list[slice_index].size;
					file_offset = slice_list[slice_index].offset;
					tail_offset = slice_list[slice_index].tail_offset;
					if (par3_ctx->noise_level >= 2){
						printf("Writing %zu bytes of slice[%I64d] on file[%u]:%I64d in input block[%d]\n", slice_size, slice_index, file_index, file_offset, block_index);
					}
					if ( (fp_write == NULL) || (file_index != file_prev) ){
						if (fp_write != NULL){	// Close previous temporary file.
							fclose(fp_write);
							fp_write = NULL;
						}
						sprintf(temp_path + 22, "%u.tmp", file_index);
						fp_write = fopen(temp_path, "r+b");
						if (fp_write == NULL){
							perror("Failed to open temporary file");
							if (fp_read != NULL)
								fclose(fp_read);
							return RET_FILE_IO_ERROR;
						}
						file_prev = file_index;
					}
					if (_fseeki64(fp_write, file_offset, SEEK_SET) != 0){
						perror("Failed to seek temporary file");
						if (fp_read != NULL)
							fclose(fp_read);
						fclose(fp_write);
						return RET_FILE_IO_ERROR;
					}
					if (fwrite(work_buf + tail_offset, 1, slice_size, fp_write) != slice_size){
						perror("Failed to write slice on temporary file");
						if (fp_read != NULL)
							fclose(fp_read);
						fclose(fp_write);
						return RET_FILE_IO_ERROR;
					}
				}

				// Goto next slice
				slice_index = slice_list[slice_index].next;
			}

			// Calculate parity bytes in the region
			if (gf_size == 2){
				gf16_region_create_parity(galois_poly, work_buf, region_size, block_size);
			} else if (gf_size == 1){
				gf8_region_create_parity(galois_poly, work_buf, region_size, block_size);
			} else {
				region_create_parity(work_buf, region_size, block_size);
			}

			// Recover (multiple & add to) lost input blocks
			rs_recover_one_all(par3_ctx, block_index, lost_count);

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
				progress_step++;
				time_now = time(NULL);
				if (time_now != time_old){
					time_old = time_now;
					// Complexity is "block_count * lost_count * block_size".
					// Because block_count is 16-bit value, "int" (32-bit signed integer) is enough.
					progress_now = (progress_step * 1000) / block_count;
					if (progress_now != progress_old){
						progress_old = progress_now;
						printf("%d.%d%%\r", progress_now / 10, progress_now % 10);	// 0.0% ~ 100.0%
					}
				}
			}
		}
	}

	// Read using recovery blocks
	for (lost_index = 0; lost_index < lost_count; lost_index++){
		block_index = recv_id[lost_index];

		// Search packet for the recovery block
		for (packet_index = 0; packet_index < packet_count; packet_index++){
			if (packet_list[packet_index].index == block_index)
				break;
		}
		if (packet_index >= packet_count){
			printf("Packet information for block[%d] is wrong.\n", block_index);
			if (fp_read != NULL)
				fclose(fp_read);
			if (fp_write != NULL)
				fclose(fp_write);
			return RET_LOGIC_ERROR;
		}

		// Read one Recovery Data Packet from a recovery file.
		slice_size = block_size;
		file_name = packet_list[packet_index].name;
		file_offset = packet_list[packet_index].offset + 48 + 40;	// offset of the recovery block data
		if (par3_ctx->noise_level >= 2){
			printf("Reading Recovery Data[%I64u] for recovery block[%d]\n", packet_index, block_index);
		}
		if ( (fp_read == NULL) || (file_name != name_prev) ){
			if (fp_read != NULL){	// Close previous recovery file.
				fclose(fp_read);
				fp_read = NULL;
			}
			fp_read = fopen(file_name, "rb");
			if (fp_read == NULL){
				perror("Failed to open recovery file");
				if (fp_write != NULL)
					fclose(fp_write);
				return RET_FILE_IO_ERROR;
			}
			name_prev = file_name;
		}
		if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
			perror("Failed to seek recovery file");
			fclose(fp_read);
			if (fp_write != NULL)
				fclose(fp_write);
			return RET_FILE_IO_ERROR;
		}
		if (fread(work_buf, 1, slice_size, fp_read) != slice_size){
			perror("Failed to read recovery data on recovery file");
			fclose(fp_read);
			if (fp_write != NULL)
				fclose(fp_write);
			return RET_FILE_IO_ERROR;
		}

		// Calculate parity bytes in the region
		if (gf_size == 2){
			gf16_region_create_parity(galois_poly, work_buf, region_size, block_size);
		} else if (gf_size == 1){
			gf8_region_create_parity(galois_poly, work_buf, region_size, block_size);
		} else {
			region_create_parity(work_buf, region_size, block_size);
		}

		// Recover (multiple & add to) lost input blocks
		rs_recover_one_all(par3_ctx, lost_id[lost_index], lost_count);

		// Print progress percent
		if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
			progress_step++;
			time_now = time(NULL);
			if (time_now != time_old){
				time_old = time_now;
				progress_now = (progress_step * 1000) / block_count;
				if (progress_now != progress_old){
					progress_old = progress_now;
					printf("%d.%d%%\r", progress_now / 10, progress_now % 10);	// 0.0% ~ 100.0%
				}
			}
		}
	}

	// Close reading file
	if (fp_read != NULL){
		if (fclose(fp_read) != 0){
			perror("Failed to close Input File");
			if (fp_write != NULL)
				fclose(fp_write);
			return RET_FILE_IO_ERROR;
		}
		fp_read = NULL;
	}
	free(work_buf);
	par3_ctx->work_buf = NULL;

	// Restore lost input blocks
	for (lost_index = 0; lost_index < lost_count; lost_index++){
		block_index = lost_id[lost_index];
		work_buf = block_data + region_size * lost_index;

		// Check parity of recovered block to confirm that calculation was correct.
		if (gf_size == 2){
			ret = gf16_region_check_parity(galois_poly, work_buf, region_size, block_size);
		} else if (gf_size == 1){
			ret = gf8_region_check_parity(galois_poly, work_buf, region_size, block_size);
		} else {
			ret = region_check_parity(work_buf, region_size, block_size);
		}
		if (ret != 0){
			printf("Parity of recovered block[%d] is different.\n", block_index);
			if (fp_write != NULL)
				fclose(fp_write);
			return RET_LOGIC_ERROR;
		}

		slice_index = block_list[block_index].slice;
		while (slice_index != -1){
			file_index = slice_list[slice_index].file;
			// If belong file is missing or damaged.
			if ( ((file_list[file_index].state & 3) != 0) && ((file_list[file_index].state & 4) == 0) ){
				// Write one lost slice on temporary file.
				slice_size = slice_list[slice_index].size;
				file_offset = slice_list[slice_index].offset;
				tail_offset = slice_list[slice_index].tail_offset;
				if (par3_ctx->noise_level >= 2){
					printf("Writing %zu bytes of slice[%I64d] on file[%u]:%I64d in lost block[%d]\n", slice_size, slice_index, file_index, file_offset, block_index);
				}
				if ( (fp_write == NULL) || (file_index != file_prev) ){
					if (fp_write != NULL){	// Close previous temporary file.
						fclose(fp_write);
						fp_write = NULL;
					}
					sprintf(temp_path + 22, "%u.tmp", file_index);
					fp_write = fopen(temp_path, "r+b");
					if (fp_write == NULL){
						perror("Failed to open temporary file");
						return RET_FILE_IO_ERROR;
					}
					file_prev = file_index;
				}
				if (_fseeki64(fp_write, file_offset, SEEK_SET) != 0){
					perror("Failed to seek temporary file");
					fclose(fp_write);
					return RET_FILE_IO_ERROR;
				}
				if (fwrite(work_buf + tail_offset, 1, slice_size, fp_write) != slice_size){
					perror("Failed to write slice on temporary file");
					fclose(fp_write);
					return RET_FILE_IO_ERROR;
				}
			}

			// Goto next slice
			slice_index = slice_list[slice_index].next;
		}
	}

	// Write chunk tails on input files
	for (file_index = 0; file_index < file_count; file_index++){
		// The input file is missing or damaged.
		if ( ((file_list[file_index].state & 3) != 0) && ((file_list[file_index].state & 4) == 0) ){
			file_size = 0;
			chunk_index = file_list[file_index].chunk;		// index of the first chunk
			chunk_num = file_list[file_index].chunk_num;	// number of chunk descriptions
			slice_index = file_list[file_index].slice;		// index of the first slice
			//printf("file[%d]: chunk = %u+%u, %s\n", file_index, chunk_index, chunk_num, file_list[file_index].name);
			while (chunk_num > 0){
				chunk_size = chunk_list[chunk_index].size;
				while ( (chunk_size >= block_size) || (chunk_size >= 40) ){	// full size slice or chunk tail slice
					slice_size = slice_list[slice_index].size;
					slice_index++;
					file_size += slice_size;
					chunk_size -= slice_size;
				}
				if (chunk_size > 0){	// tiny chunk tail
					file_offset = file_size;	// Offset of chunk tail
					slice_size = chunk_size;	// Tiny chunk tail was stored in File Packet.
					file_size += slice_size;

					// copy 1 ~ 39 bytes
					memcpy(buf_tail, &(chunk_list[chunk_index].tail_crc), 8);
					memcpy(buf_tail + 8, chunk_list[chunk_index].tail_hash, 16);
					memcpy(buf_tail + 24, &(chunk_list[chunk_index].tail_block), 8);
					memcpy(buf_tail + 32, &(chunk_list[chunk_index].tail_offset), 8);

					// Write tail slice on temporary file.
					if (par3_ctx->noise_level >= 2){
						printf("Writing %zu bytes of chunk[%u] tail on file[%u]:%I64d\n", slice_size, chunk_index, file_index, file_offset);
					}
					if ( (fp_write == NULL) || (file_index != file_prev) ){
						if (fp_write != NULL){	// Close previous temporary file.
							fclose(fp_write);
							fp_write = NULL;
						}
						sprintf(temp_path + 22, "%u.tmp", file_index);
						fp_write = fopen(temp_path, "r+b");
						if (fp_write == NULL){
							perror("Failed to open temporary file");
							return RET_FILE_IO_ERROR;
						}
						file_prev = file_index;
					}
					if (_fseeki64(fp_write, file_offset, SEEK_SET) != 0){
						perror("Failed to seek temporary file");
						fclose(fp_write);
						return RET_FILE_IO_ERROR;
					}
					if (fwrite(buf_tail, 1, slice_size, fp_write) != slice_size){
						perror("Failed to write tiny slice on temporary file");
						fclose(fp_write);
						return RET_FILE_IO_ERROR;
					}
				}

				chunk_index++;
				chunk_num--;
			}

			if (file_size != file_list[file_index].size){
				printf("file size is bad. %s\n", temp_path);
				return RET_LOGIC_ERROR;
			} else {
				file_list[file_index].state |= 0x100;
			}
		}
	}

	// Close writing file
	if (fp_write != NULL){
		if (fclose(fp_write) != 0){
			perror("Failed to close temporary File");
			return RET_FILE_IO_ERROR;
		}
	}

	if (par3_ctx->noise_level >= 0){
		clock_now = clock() - clock_now;
		printf("done in %.1f seconds.\n", (double)clock_now / CLOCKS_PER_SEC);
	}

	return 0;
}

// This keeps all input blocks and recovery blocks partially by spliting every block.
int recover_lost_block_split(PAR3_CTX *par3_ctx, char *temp_path, uint64_t lost_count)
{
	void *gf_table, *matrix;
	char *name_prev, *file_name;
	uint8_t buf_tail[40];
	uint8_t *block_data, *buf_p;
	uint8_t gf_size;
	int galois_poly, *lost_id, *recv_id;
	int ret;
	int progress_old, progress_now;
	uint32_t split_count;
	uint32_t file_count, file_index, file_prev;
	uint32_t chunk_index, chunk_num;
	size_t io_size;
	int64_t slice_index, file_offset;
	uint64_t block_index, lost_index;
	uint64_t block_size, block_count;
	uint64_t alloc_size, region_size, split_size;
	uint64_t data_size, part_size, split_offset;
	uint64_t tail_offset, tail_gap;
	uint64_t packet_count, packet_index;
	uint64_t file_size, chunk_size;
	uint64_t progress_total, progress_step;
	PAR3_BLOCK_CTX *block_list;
	PAR3_SLICE_CTX *slice_list;
	PAR3_CHUNK_CTX *chunk_list;
	PAR3_FILE_CTX *file_list;
	PAR3_PKT_CTX *packet_list;
	FILE *fp;
	time_t time_old, time_now;
	clock_t clock_now;

	//printf("\n ecc_method = 0x%x, lost_count = %d\n", par3_ctx->ecc_method, lost_count);

	file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	gf_size = par3_ctx->gf_size;
	galois_poly = par3_ctx->galois_poly;
	gf_table = par3_ctx->galois_table;
	matrix = par3_ctx->matrix;
	lost_id = par3_ctx->id_list;
	recv_id = lost_id + lost_count;
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;
	chunk_list = par3_ctx->chunk_list;
	file_list = par3_ctx->input_file_list;
	packet_list = par3_ctx->recv_packet_list;
	packet_count = par3_ctx->recv_packet_count;

	// Set required memory size at first
	region_size = (block_size + 4 + 3) & ~3;
	alloc_size = region_size * (block_count + lost_count);

	// for test split
	//par3_ctx->memory_limit = (alloc_size + 2) / 3;

	// Limited memory usage
	if ( (par3_ctx->memory_limit > 0) && (alloc_size > par3_ctx->memory_limit) ){
		split_count = (uint32_t)((alloc_size + par3_ctx->memory_limit - 1) / par3_ctx->memory_limit);
		split_size = (block_size + split_count - 1) / split_count;	// This is splitted block size to fit in limited memory.
		split_size = (split_size + 1) & ~1;	// aligned to 2 bytes for 8 or 16-bit Galois Field
		if (par3_ctx->noise_level >= 1){
			printf("\nSplit block to %u pieces of %I64u bytes.\n", split_count, split_size);
		}
	} else {
		split_count = 1;
		split_size = block_size;
	}

	// Allocate memory to keep all splitted blocks.
	region_size = (split_size + 4 + 3) & ~3;
	alloc_size = region_size * (block_count + lost_count);
	//printf("region_size = %I64u, alloc_size = %I64u\n", region_size, alloc_size);
	block_data = malloc(alloc_size);
	if (block_data == NULL){
		perror("Failed to allocate memory for block data");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->block_data = block_data;

	// Base name of temporary file
	sprintf(temp_path, "par3_%02X%02X%02X%02X%02X%02X%02X%02X_",
			par3_ctx->set_id[0], par3_ctx->set_id[1], par3_ctx->set_id[2], par3_ctx->set_id[3],
			par3_ctx->set_id[4], par3_ctx->set_id[5], par3_ctx->set_id[6], par3_ctx->set_id[7]);

	if (par3_ctx->noise_level >= 0){
		printf("\nRecovering lost input blocks:\n");
		progress_total = (block_count * lost_count + block_count * 2 + lost_count) * split_count;
		progress_step = 0;
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}

	// This file access style would support all Error Correction Codes.
	file_prev = 0xFFFFFFFF;
	fp = NULL;
	for (split_offset = 0; split_offset < block_size; split_offset += split_size){
		buf_p = block_data;	// Starting position of input blocks
		name_prev = NULL;

		// Read available input blocks on memory
		for (block_index = 0; block_index < block_count; block_index++){
			data_size = block_list[block_index].size;
			part_size = data_size - split_offset;
			if (part_size > split_size)
				part_size = split_size;

			// Read block data from found file.
			if (block_list[block_index].state & 4){	// Full size data is available.
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
				file_name = slice_list[slice_index].find_name;
				file_offset = slice_list[slice_index].find_offset + split_offset;
				io_size = part_size;
				if (par3_ctx->noise_level >= 2){
					printf("Reading %zu bytes of slice[%I64d] for input block[%I64u]\n", io_size, slice_index, block_index);
				}
				if ( (fp == NULL) || (file_name != name_prev) ){
					if (fp != NULL){	// Close previous input file.
						fclose(fp);
						fp = NULL;
					}
					fp = fopen(file_name, "rb");
					if (fp == NULL){
						perror("Failed to open Input File");
						return RET_FILE_IO_ERROR;
					}
					name_prev = file_name;
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

			// All tail data is available. (one tail or packed tails)
			} else if ( (data_size > split_offset) && (block_list[block_index].state & 16) ){
				if (par3_ctx->noise_level >= 2){
					printf("Reading %I64u bytes for input block[%I64u]\n", part_size, block_index);
				}
				tail_offset = split_offset;
				while (tail_offset < split_offset + part_size){	// Read tails until data end.
					slice_index = block_list[block_index].slice;
					while (slice_index != -1){
						//printf("block = %d, size = %I64u, offset = %I64u, slice = %I64d\n", block_index, data_size, tail_offset, slice_index);
						// Even when chunk tails are overlaped, it will find tail slice of next position.
						if ( (slice_list[slice_index].tail_offset + slice_list[slice_index].size > tail_offset) &&
								(slice_list[slice_index].tail_offset <= tail_offset) ){
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
					file_name = slice_list[slice_index].find_name;
					file_offset = slice_list[slice_index].find_offset + tail_gap;
					io_size = slice_list[slice_index].size - tail_gap;

					if ( (fp == NULL) || (file_name != name_prev) ){
						if (fp != NULL){	// Close previous input file.
							fclose(fp);
							fp = NULL;
						}
						fp = fopen(file_name, "rb");
						if (fp == NULL){
							perror("Failed to open Input File");
							return RET_FILE_IO_ERROR;
						}
						name_prev = file_name;
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

			} else {	// The input block was lost.
				data_size = 0;	// Mark of lost block
			}

			if (data_size > split_offset){	// When there is slice data to process.
				if (part_size < split_size)
					memset(buf_p + part_size, 0, split_size - part_size);	// Zero fill rest bytes
				// No need to calculate CRC of reading block, because it will check recovered block later.

				// Calculate parity bytes in the region
				if (gf_size == 2){
					gf16_region_create_parity(galois_poly, buf_p, region_size, split_size);
				} else if (gf_size == 1){
					gf8_region_create_parity(galois_poly, buf_p, region_size, split_size);
				} else {
					region_create_parity(buf_p, region_size, split_size);
				}

			} else {	// Zero fill partial input block
				memset(buf_p, 0, region_size);
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
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

		// Read using recovery blocks
		part_size = block_size - split_offset;
		if (part_size > split_size)
			part_size = split_size;
		io_size = part_size;
		for (lost_index = 0; lost_index < lost_count; lost_index++){
			block_index = recv_id[lost_index];

			// Search packet for the recovery block
			for (packet_index = 0; packet_index < packet_count; packet_index++){
				if (packet_list[packet_index].index == block_index)
					break;
			}
			if (packet_index >= packet_count){
				printf("Packet information for block[%I64u] is wrong.\n", block_index);
				if (fp != NULL)
					fclose(fp);
				return RET_LOGIC_ERROR;
			}

			// Read one Recovery Data Packet from a recovery file.
			file_name = packet_list[packet_index].name;
			file_offset = packet_list[packet_index].offset + 48 + 40 + split_offset;	// offset of the recovery block data
			if (par3_ctx->noise_level >= 2){
				printf("Reading Recovery Data[%I64u] for recovery block[%I64u]\n", packet_index, block_index);
			}
			if ( (fp == NULL) || (file_name != name_prev) ){
				if (fp != NULL){	// Close previous recovery file.
					fclose(fp);
					fp = NULL;
				}
				fp = fopen(file_name, "rb");
				if (fp == NULL){
					perror("Failed to open recovery file");
					return RET_FILE_IO_ERROR;
				}
				name_prev = file_name;
			}
			if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
				perror("Failed to seek recovery file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			if (fread(buf_p, 1, io_size, fp) != io_size){
				perror("Failed to read recovery data on recovery file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}

			// Calculate parity bytes in the region
			if (gf_size == 2){
				gf16_region_create_parity(galois_poly, buf_p, region_size, split_size);
			} else if (gf_size == 1){
				gf8_region_create_parity(galois_poly, buf_p, region_size, split_size);
			} else {
				region_create_parity(buf_p, region_size, split_size);
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
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
				perror("Failed to close file");
				return RET_FILE_IO_ERROR;
			}
			fp = NULL;
		}

		// Recover (multiple & add to) lost input blocks
		if (par3_ctx->ecc_method & 1){	// Reed-Solomon Erasure Codes
			rs_recover_all(par3_ctx, region_size, (int)lost_count, progress_total, progress_step);
		}
		if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
			progress_step += block_count * lost_count;
			time_old = time(NULL);
		}

		// Restore all input blocks
		buf_p = block_data;
		lost_index = 0;
		for (block_index = 0; block_index < block_count; block_index++){
			if (block_index == lost_id[lost_index]){	// recovered input block
				lost_index++;

				// Check parity of recovered block to confirm that calculation was correct.
				if (gf_size == 2){
					ret = gf16_region_check_parity(galois_poly, buf_p, region_size, split_size);
				} else if (gf_size == 1){
					ret = gf8_region_check_parity(galois_poly, buf_p, region_size, split_size);
				} else {
					ret = region_check_parity(buf_p, region_size, split_size);
				}
				if (ret != 0){
					printf("Parity of recovered block[%I64u] is different.\n", block_index);
					if (fp != NULL)
						fclose(fp);
					return RET_LOGIC_ERROR;
				}
			}

			slice_index = block_list[block_index].slice;
			while (slice_index != -1){
				file_index = slice_list[slice_index].file;
				// If belong file is missing or damaged.
				if ( ((file_list[file_index].state & 3) != 0) && ((file_list[file_index].state & 4) == 0) ){
					data_size = slice_list[slice_index].size;
					file_offset = slice_list[slice_index].offset;
					tail_offset = slice_list[slice_index].tail_offset;
					if ( (tail_offset + data_size > split_offset) && (tail_offset < split_offset + split_size) ){
						// Write a part of lost slice on temporary file.
						if (tail_offset < split_offset){
							tail_gap = 0;	// This tail slice may start before split_offset.
							file_offset = file_offset + split_offset - tail_offset;
							part_size = tail_offset + data_size - split_offset;
							if (part_size > split_size)
								part_size = split_size;
						} else {
							tail_gap = tail_offset - split_offset;
							part_size = data_size;
							if (part_size > split_offset + split_size - tail_offset)
								part_size = split_offset + split_size - tail_offset;
						}
						io_size = part_size;
						if (par3_ctx->noise_level >= 2){
							printf("Writing %zu bytes of slice[%I64d] on file[%u]:%I64d in block[%I64u]\n", io_size, slice_index, file_index, file_offset, block_index);
						}
						if ( (fp == NULL) || (file_index != file_prev) ){
							if (fp != NULL){	// Close previous temporary file.
								fclose(fp);
								fp = NULL;
							}
							sprintf(temp_path + 22, "%u.tmp", file_index);
							fp = fopen(temp_path, "r+b");
							if (fp == NULL){
								perror("Failed to open temporary file");
								return RET_FILE_IO_ERROR;
							}
							file_prev = file_index;
						}
						if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
							perror("Failed to seek temporary file");
							fclose(fp);
							return RET_FILE_IO_ERROR;
						}
						if (fwrite(buf_p + tail_gap, 1, io_size, fp) != io_size){
							perror("Failed to write slice on temporary file");
							fclose(fp);
							return RET_FILE_IO_ERROR;
						}
					}
				}

				// Goto next slice
				slice_index = slice_list[slice_index].next;
			}

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
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
	}

	// Write chunk tails on input files
	for (file_index = 0; file_index < file_count; file_index++){
		// The input file is missing or damaged.
		if ( ((file_list[file_index].state & 3) != 0) && ((file_list[file_index].state & 4) == 0) ){
			file_size = 0;
			chunk_index = file_list[file_index].chunk;		// index of the first chunk
			chunk_num = file_list[file_index].chunk_num;	// number of chunk descriptions
			slice_index = file_list[file_index].slice;		// index of the first slice
			//printf("file[%d]: chunk = %u+%u, %s\n", file_index, chunk_index, chunk_num, file_list[file_index].name);
			while (chunk_num > 0){
				chunk_size = chunk_list[chunk_index].size;
				while ( (chunk_size >= block_size) || (chunk_size >= 40) ){	// full size slice or chunk tail slice
					data_size = slice_list[slice_index].size;
					slice_index++;
					file_size += data_size;
					chunk_size -= data_size;
				}
				if (chunk_size > 0){	// tiny chunk tail
					file_offset = file_size;	// Offset of chunk tail
					io_size = chunk_size;	// Tiny chunk tail was stored in File Packet.
					file_size += io_size;

					// copy 1 ~ 39 bytes
					memcpy(buf_tail, &(chunk_list[chunk_index].tail_crc), 8);
					memcpy(buf_tail + 8, chunk_list[chunk_index].tail_hash, 16);
					memcpy(buf_tail + 24, &(chunk_list[chunk_index].tail_block), 8);
					memcpy(buf_tail + 32, &(chunk_list[chunk_index].tail_offset), 8);

					// Write tail slice on temporary file.
					if (par3_ctx->noise_level >= 2){
						printf("Writing %zu bytes of chunk[%u] tail on file[%u]:%I64d\n", io_size, chunk_index, file_index, file_offset);
					}
					if ( (fp == NULL) || (file_index != file_prev) ){
						if (fp != NULL){	// Close previous temporary file.
							fclose(fp);
							fp = NULL;
						}
						sprintf(temp_path + 22, "%u.tmp", file_index);
						fp = fopen(temp_path, "r+b");
						if (fp == NULL){
							perror("Failed to open temporary file");
							return RET_FILE_IO_ERROR;
						}
						file_prev = file_index;
					}
					if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
						perror("Failed to seek temporary file");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
					if (fwrite(buf_tail, 1, io_size, fp) != io_size){
						perror("Failed to write tiny slice on temporary file");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
				}

				chunk_index++;
				chunk_num--;
			}

			if (file_size != file_list[file_index].size){
				printf("file size is bad. %s\n", temp_path);
				return RET_LOGIC_ERROR;
			} else {
				file_list[file_index].state |= 0x100;
			}
		}
	}

	// Close writing file
	if (fp != NULL){
		if (fclose(fp) != 0){
			perror("Failed to close temporary File");
			return RET_FILE_IO_ERROR;
		}
	}

	if (par3_ctx->noise_level >= 0){
		clock_now = clock() - clock_now;
		printf("done in %.1f seconds.\n", (double)clock_now / CLOCKS_PER_SEC);
	}

	return 0;
}

