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
keep all lost input blocks on memory

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
	char *file_read, *file_name;
	uint8_t *work_buf, buf_tail[40];
	uint8_t *block_data, gf_size;
	int *lost_id, *recv_id;
	int block_count, block_index;
	int x, y, factor;
	int progress_old, progress_now, progress;
	uint32_t file_count, file_index, file_write;
	uint32_t chunk_index, chunk_num;
	size_t slice_size;
	int64_t slice_index, file_offset;
	uint64_t block_size, region_size, data_size, tail_offset;
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
	gf_table = par3_ctx->galois_table;
	matrix = par3_ctx->matrix;
	lost_id = par3_ctx->id_list;
	recv_id = lost_id + lost_count;
	block_data = par3_ctx->block_data;
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;
	chunk_list = par3_ctx->chunk_list;
	file_list = par3_ctx->input_file_list;
	packet_list = par3_ctx->rec_data_packet_list;
	packet_count = par3_ctx->rec_data_packet_count;

	region_size = (block_size + 1 + 3) & ~3;

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
		progress = 0;
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}

	// Read available input blocks
	file_read = NULL;
	file_write = 0xFFFFFFFF;
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
			slice_size = slice_list[slice_index].size;
			file_offset = slice_list[slice_index].find_offset;
			file_name = slice_list[slice_index].find_name;
			if (par3_ctx->noise_level >= 2){
				printf("Reading %zu bytes of slice[%I64d] for input block[%d]\n", slice_size, slice_index, block_index);
			}
			if ( (fp_read == NULL) || (file_name != file_read) ){
				if (fp_read != NULL){	// Close previous input file.
					fclose(fp_read);
					fp_read = NULL;
				}
				fp_read = fopen(file_name, "rb");
				if (fp_read == NULL){
					perror("Failed to open input file");
					if (fp_write != NULL)
						fclose(fp_write);
					return RET_FILE_IO_ERROR;
				}
				file_read = file_name;
			}
			if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
				perror("Failed to seek input file");
				fclose(fp_read);
				if (fp_write != NULL)
					fclose(fp_write);
				return RET_FILE_IO_ERROR;
			}
			if (fread(work_buf, 1, slice_size, fp_read) != slice_size){
				perror("Failed to read full slice on input file");
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
				slice_size = slice_list[slice_index].size;
				file_offset = slice_list[slice_index].find_offset;
				file_name = slice_list[slice_index].find_name;
				if ( (fp_read == NULL) || (file_name != file_read) ){
					if (fp_read != NULL){	// Close previous input file.
						fclose(fp_read);
						fp_read = NULL;
					}
					fp_read = fopen(file_name, "rb");
					if (fp_read == NULL){
						perror("Failed to open input file");
						if (fp_write != NULL)
							fclose(fp_write);
						return RET_FILE_IO_ERROR;
					}
					file_read = file_name;
				}
				if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
					perror("Failed to seek input file");
					fclose(fp_read);
					if (fp_write != NULL)
						fclose(fp_write);
					return RET_FILE_IO_ERROR;
				}
				if (fread(work_buf + tail_offset, 1, slice_size, fp_read) != slice_size){
					perror("Failed to read tail slice on input file");
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
					if ( (fp_write == NULL) || (file_index != file_write) ){
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
						file_write = file_index;
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
			region_create_parity(work_buf, region_size, block_size);

			// Recover (multiple & add to) lost input blocks
			for (y = 0; y < lost_count; y++){
				if (gf_size == 2){
					factor = ((uint16_t *)matrix)[ block_count * y + block_index ];
					gf16_region_multiply(gf_table, work_buf, factor, region_size, block_data + region_size * y, 1);
				} else {
					factor = ((uint8_t *)matrix)[ block_count * y + block_index ];
					gf8_region_multiply(gf_table, work_buf, factor, region_size, block_data + region_size * y, 1);
				}
				//printf("lost block[%d] += input block[%d] * %2x\n", lost_id[y], block_index, factor);
			}

			// Print progress percent
			progress++;
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
				time_now = time(NULL);
				if (time_now != time_old){
					time_old = time_now;
					// Complexity is "block_count * lost_count * block_size".
					// Because block_count is 16-bit value, "int" (32-bit signed integer) is enough.
					progress_now = (progress * 1000) / block_count;
					if (progress_now != progress_old){
						progress_old = progress_now;
						printf("%d.%d%%\r", progress_now / 10, progress_now % 10);	// 0.0% ~ 100.0%
					}
				}
			}
		}
	}

	// Read using recovery blocks
	for (x = 0; x < lost_count; x++){
		block_index = recv_id[x];

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
		if ( (fp_read == NULL) || (file_name != file_read) ){
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
			file_read = file_name;
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
		region_create_parity(work_buf, region_size, block_size);

		// Recover (multiple & add to) lost input blocks
		for (y = 0; y < lost_count; y++){
			if (gf_size == 2){
				factor = ((uint16_t *)matrix)[ block_count * y + lost_id[x] ];
				gf16_region_multiply(gf_table, work_buf, factor, region_size, block_data + region_size * y, 1);
			} else {
				factor = ((uint8_t *)matrix)[ block_count * y + lost_id[x] ];
				gf8_region_multiply(gf_table, work_buf, factor, region_size, block_data + region_size * y, 1);
			}
			//printf("lost block[%d] += recovery block[%d] * %2x\n", lost_id[y], block_index, factor);
		}

		// Print progress percent
		progress++;
		if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 1) ){
			time_now = time(NULL);
			if (time_now != time_old){
				time_old = time_now;
				progress_now = (progress * 1000) / block_count;
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
			perror("Failed to close input file");
			if (fp_write != NULL)
				fclose(fp_write);
			return RET_FILE_IO_ERROR;
		}
		fp_read = NULL;
	}
	free(work_buf);
	par3_ctx->work_buf = NULL;

	// Restore lost input blocks
	for (y = 0; y < lost_count; y++){
		block_index = lost_id[y];
		work_buf = block_data + region_size * y;

		// Check parity of recovered block to confirm that calculation was correct.
		if (region_check_parity(work_buf, region_size, block_size) != 0){
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
				if ( (fp_write == NULL) || (file_index != file_write) ){
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
					file_write = file_index;
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
					if ( (fp_write == NULL) || (file_index != file_write) ){
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
						file_write = file_index;
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

