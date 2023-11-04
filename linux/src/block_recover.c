// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

/* Redefinition of _FILE_OFFSET_BITS must happen BEFORE including stdio.h */
#ifdef __linux__
#define _FILE_OFFSET_BITS 64
#define _fseeki64 fseeko
#define _fileno fileno
#define _chsize_s ftruncate
#elif _WIN32
#endif


#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if __linux__

#include <unistd.h>

#elif _WIN32

// MSVC headers
#include <io.h>

#endif

#include "libpar3.h"
#include "galois.h"
#include "hash.h"
#include "reedsolomon.h"
#include "leopard/leopard.h"


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
	recv_id = par3_ctx->recv_id_list;
	lost_id = recv_id + lost_count;
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

	// Store available input blocks on memory
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
			if (par3_ctx->noise_level >= 3){
				printf("Reading %zu bytes of slice[%"PRIi64"] for input block[%d]\n", slice_size, slice_index, block_index);
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
			if (par3_ctx->noise_level >= 3){
				printf("Reading %"PRIu64" bytes for input block[%d]\n", data_size, block_index);
			}
			tail_offset = 0;
			while (tail_offset < data_size){	// Read tails until data end.
				slice_index = block_list[block_index].slice;
				while (slice_index != -1){
					//printf("block = %d, size = %"PRIu64", offset = %"PRIu64", slice = %"PRIi64"\n", block_index, data_size, tail_offset, slice_index);
					// Even when chunk tails are overlaped, it will find tail slice of next position.
					if ( (slice_list[slice_index].tail_offset + slice_list[slice_index].size > tail_offset)
							&& (slice_list[slice_index].tail_offset <= tail_offset) ){
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

		} else {	// The input block was lost.
			data_size = 0;	// Mark of lost block
		}

		if (data_size > 0){	// The block data is available.
			// Zero fill rest bytes
			memset(work_buf + data_size, 0, region_size - data_size);

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
					if (par3_ctx->noise_level >= 3){
						printf("Writing %zu bytes of slice[%"PRIi64"] on file[%u]:%"PRIi64" in input block[%d]\n", slice_size, slice_index, file_index, file_offset, block_index);
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
				gf16_region_create_parity(galois_poly, work_buf, region_size);
			} else if (gf_size == 1){
				gf8_region_create_parity(galois_poly, work_buf, region_size);
			} else {
				region_create_parity(work_buf, region_size);
			}

			// Recover (multiple & add to) lost input blocks
			rs_recover_one_all(par3_ctx, block_index, lost_count);

			// Print progress percent
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
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
		if (par3_ctx->noise_level >= 3){
			printf("Reading Recovery Data[%"PRIu64"] for recovery block[%d]\n", packet_index, block_index);
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
		// Zero fill rest bytes
		memset(work_buf + block_size, 0, region_size - block_size);

		// Calculate parity bytes in the region
		if (gf_size == 2){
			gf16_region_create_parity(galois_poly, work_buf, region_size);
		} else if (gf_size == 1){
			gf8_region_create_parity(galois_poly, work_buf, region_size);
		} else {
			region_create_parity(work_buf, region_size);
		}

		// Recover (multiple & add to) lost input blocks
		rs_recover_one_all(par3_ctx, lost_id[lost_index], lost_count);

		// Print progress percent
		if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
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
			ret = gf16_region_check_parity(galois_poly, work_buf, region_size);
		} else if (gf_size == 1){
			ret = gf8_region_check_parity(galois_poly, work_buf, region_size);
		} else {
			ret = region_check_parity(work_buf, region_size);
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
				if (par3_ctx->noise_level >= 3){
					printf("Writing %zu bytes of slice[%"PRIi64"] on file[%u]:%"PRIi64" in lost block[%d]\n", slice_size, slice_index, file_index, file_offset, block_index);
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
				if (chunk_size == 0){	// Unprotected Chunk Description
					// Unprotected chunk will be filled by zeros after repair.
					file_size += chunk_list[chunk_index].block;
					if (chunk_num == 1){	// When unprotected chunk is the last in the input file, set end of file.
						int file_no;
						if (par3_ctx->noise_level >= 3){
							printf("Zero padding unprotected chunk[%u] on file[%u]:%"PRIi64"\n", chunk_index, file_index, file_size);
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
						file_no = _fileno(fp_write);
						if (file_no < 0){
							perror("Failed to seek temporary file");
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						} else {
							if (_chsize_s(file_no, file_size) != 0){
								perror("Failed to resize temporary file");
								fclose(fp_write);
								return RET_FILE_IO_ERROR;
							}
						}
					}

				} else {	// Protected Chunk Description
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
						if (par3_ctx->noise_level >= 3){
							printf("Writing %zu bytes of chunk[%u] tail on file[%u]:%"PRIi64"\n", slice_size, chunk_index, file_index, file_offset);
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

	// Release some allocated memory
	free(recv_id);
	par3_ctx->recv_id_list = NULL;
	free(matrix);
	par3_ctx->matrix = NULL;

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
	int galois_poly, *recv_id;
	int ret;
	int progress_old, progress_now;
	uint32_t split_count;
	uint32_t file_count, file_index, file_prev;
	uint32_t chunk_index, chunk_num;
	size_t io_size;
	int64_t slice_index, file_offset;
	uint64_t block_index, lost_index;
	uint64_t block_size, block_count, max_recovery_block;
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

	// For Leopard-RS library
	uint32_t work_count;
	uint8_t **original_data = NULL, **recovery_data = NULL, **work_data = NULL;

	file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	max_recovery_block = par3_ctx->max_recovery_block;
	gf_size = par3_ctx->gf_size;
	galois_poly = par3_ctx->galois_poly;
	gf_table = par3_ctx->galois_table;
	matrix = par3_ctx->matrix;
	recv_id = par3_ctx->recv_id_list;
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;
	chunk_list = par3_ctx->chunk_list;
	file_list = par3_ctx->input_file_list;
	packet_list = par3_ctx->recv_packet_list;
	packet_count = par3_ctx->recv_packet_count;

	// Set required memory size at first
	if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
		ret = leo_init();	// Initialize Leopard-RS library.
		if (ret != 0){
			printf("Failed to initialize Leopard-RS library (%d)\n", ret);
			return RET_LOGIC_ERROR;
		}
		work_count = leo_decode_work_count((uint32_t)block_count, (uint32_t)max_recovery_block);
		//printf("Leopard-RS: work_count = %u\n", work_count);
		// Leopard-RS requires multiple of 64 bytes for SIMD.
		region_size = (block_size + 4 + 63) & ~63;
		alloc_size = region_size * (block_count + work_count);

	} else {	// Reed-Solomon Erasure Codes
		// Mmeory alignment is 4 bytes.
		region_size = (block_size + 4 + 3) & ~3;
		alloc_size = region_size * (block_count + lost_count);
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
			printf("\nSplit block to %u pieces of %"PRIu64" bytes.\n", split_count, split_size);
		}
	} else {
		split_count = 1;
		split_size = block_size;
	}

	// Allocate memory to keep all splitted blocks.
	if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
		// Leopard-RS requires alignment of 64 bytes.
		// At reading time, it stores using recovery blocks in place of lost input blocks.
		// Recovered lost blocks are stored in work buffer.
		// So, it will write back recovered data from there.
		region_size = (split_size + 4 + 63) & ~63;
		alloc_size = region_size * (block_count + work_count);
		if (par3_ctx->noise_level >= 2){
			printf("\nAligned size of block data = %"PRIu64"\n", region_size);
			printf("Allocated memory size = %"PRIu64" * (%"PRIu64" + %u) = %"PRIu64"\n", region_size, block_count, work_count, alloc_size);
		}
	} else {	// Reed-Solomon Erasure Codes
		region_size = (split_size + 4 + 3) & ~3;
		alloc_size = region_size * (block_count + lost_count);
		if (par3_ctx->noise_level >= 2){
			printf("\nAligned size of block data = %"PRIu64"\n", region_size);
			printf("Allocated memory size = %"PRIu64" * (%"PRIu64" + %"PRIu64") = %"PRIu64"\n", region_size, block_count, lost_count, alloc_size);
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
		original_data = malloc(sizeof(block_data) * (block_count + max_recovery_block + work_count));
		if (original_data == NULL){
			perror("Failed to allocate memory for Leopard-RS");
			return RET_MEMORY_ERROR;
		}
		recovery_data = original_data + block_count;
		for (block_index = 0; block_index < max_recovery_block; block_index++){
			// At first, clear position of recovery block.
			recovery_data[block_index] = NULL;
		}
		buf_p = block_data;
		lost_index = 0;
		for (block_index = 0; block_index < block_count; block_index++){
			if ((block_list[block_index].state & (4 | 16)) == 0){	// lost input block
				original_data[block_index] = NULL;
				// Using recovery blocks will be stored in place of lost input blocks.
				recovery_data[ recv_id[lost_index] ] = buf_p;
				lost_index++;
			} else {
				original_data[block_index] = buf_p;
			}
			buf_p += region_size;
		}
		work_data = recovery_data + max_recovery_block;
		for (block_index = 0; block_index < work_count; block_index++){
			work_data[block_index] = buf_p;
			buf_p += region_size;
		}
		par3_ctx->matrix = original_data;	// Release this later
	}

	// Base name of temporary file
	sprintf(temp_path, "par3_%02X%02X%02X%02X%02X%02X%02X%02X_",
			par3_ctx->set_id[0], par3_ctx->set_id[1], par3_ctx->set_id[2], par3_ctx->set_id[3],
			par3_ctx->set_id[4], par3_ctx->set_id[5], par3_ctx->set_id[6], par3_ctx->set_id[7]);

	if (par3_ctx->noise_level >= 0){
		printf("\nRecovering lost input blocks:\n");
		// block_count = Number of input block (read)
		// lost_count = Number of using recovery block (read)
		// block_count * lost_count = Number of multiplication
		// block_count = Number of input block (write)
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

		// Store available input blocks on memory
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
					printf("Mapping information for block[%"PRIu64"] is wrong.\n", block_index);
					if (fp != NULL)
						fclose(fp);
					return RET_LOGIC_ERROR;
				}

				// Read a part of slice from a file.
				file_name = slice_list[slice_index].find_name;
				file_offset = slice_list[slice_index].find_offset + split_offset;
				io_size = part_size;
				if (par3_ctx->noise_level >= 3){
					printf("Reading %zu bytes of slice[%"PRIi64"] for input block[%"PRIu64"]\n", io_size, slice_index, block_index);
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
				if (par3_ctx->noise_level >= 3){
					printf("Reading %"PRIu64" bytes for input block[%"PRIu64"]\n", part_size, block_index);
				}
				tail_offset = split_offset;
				while (tail_offset < split_offset + part_size){	// Read tails until data end.
					slice_index = block_list[block_index].slice;
					while (slice_index != -1){
						//printf("block = %d, size = %"PRIu64", offset = %"PRIu64", slice = %"PRIi64"\n", block_index, data_size, tail_offset, slice_index);
						// Even when chunk tails are overlaped, it will find tail slice of next position.
						if ( (slice_list[slice_index].tail_offset + slice_list[slice_index].size > tail_offset)
								&& (slice_list[slice_index].tail_offset <= tail_offset) ){
							break;
						}
						slice_index = slice_list[slice_index].next;
					}
					if (slice_index == -1){	// When there is no valid slice.
						printf("Mapping information for block[%"PRIu64"] is wrong.\n", block_index);
						if (fp != NULL)
							fclose(fp);
						return RET_LOGIC_ERROR;
					}

					// Read one slice from a file.
					tail_gap = tail_offset - slice_list[slice_index].tail_offset;	// This tail slice may start before tail_offset.
					file_name = slice_list[slice_index].find_name;
					file_offset = slice_list[slice_index].find_offset + tail_gap;
					io_size = slice_list[slice_index].size - tail_gap;
					if (io_size > part_size)
						io_size = part_size;
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

			} else {	// The input block was lost, or empty space in tail block.
				if (block_list[block_index].state & 16){
					// Zero fill partial input block
					memset(buf_p, 0, region_size);
				} else if (par3_ctx->ecc_method & 1){	// Cauchy Reed-Solomon Codes
					// Zero fill lost input block
					memset(buf_p, 0, region_size);
				}
				data_size = 0;	// No need to calculate parity.
			}

			if (data_size > split_offset){	// When there is slice data to process.
				memset(buf_p + part_size, 0, region_size - part_size);	// Zero fill rest bytes
				// No need to calculate CRC of reading block, because it will check recovered block later.

				if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
					if (gf_size == 2){
						leo_region_create_parity(buf_p, region_size);
					} else {
						region_create_parity(buf_p, region_size);
					}
				} else {
					// Calculate parity bytes in the region
					if (gf_size == 2){
						gf16_region_create_parity(galois_poly, buf_p, region_size);
					} else if (gf_size == 1){
						gf8_region_create_parity(galois_poly, buf_p, region_size);
					} else {
						region_create_parity(buf_p, region_size);
					}
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

		// Read using recovery blocks
		part_size = block_size - split_offset;
		if (part_size > split_size)
			part_size = split_size;
		io_size = part_size;
		for (lost_index = 0; lost_index < lost_count; lost_index++){
			block_index = recv_id[lost_index];	// Index of the recovery block
			if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
				buf_p = recovery_data[block_index];	// Address of the recovery block
			}

			// Search packet for the recovery block
			for (packet_index = 0; packet_index < packet_count; packet_index++){
				if (packet_list[packet_index].index == block_index)
					break;
			}
			if (packet_index >= packet_count){
				printf("Packet information for block[%"PRIu64"] is wrong.\n", block_index);
				if (fp != NULL)
					fclose(fp);
				return RET_LOGIC_ERROR;
			}

			// Read one Recovery Data Packet from a recovery file.
			file_name = packet_list[packet_index].name;
			file_offset = packet_list[packet_index].offset + 48 + 40 + split_offset;	// offset of the recovery block data
			if (par3_ctx->noise_level >= 3){
				printf("Reading Recovery Data[%"PRIu64"] for recovery block[%"PRIu64"]\n", packet_index, block_index);
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
			memset(buf_p + part_size, 0, region_size - part_size);	// Zero fill rest bytes

			if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
				// Because GF Multiplication doesn't work on FFT, it does XOR only.
				if (gf_size == 2){
					leo_region_create_parity(buf_p, region_size);
				} else {
					region_create_parity(buf_p, region_size);
				}
			} else {
				// Calculate parity bytes in the region
				if (gf_size == 2){
					gf16_region_create_parity(galois_poly, buf_p, region_size);
				} else if (gf_size == 1){
					gf8_region_create_parity(galois_poly, buf_p, region_size);
				} else {
					region_create_parity(buf_p, region_size);
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

		// Close recovery file, because next reading will be Input File.
		if (fp != NULL){
			if (fclose(fp) != 0){
				perror("Failed to close recovery file");
				return RET_FILE_IO_ERROR;
			}
			fp = NULL;
		}

/*
if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
	printf("\n read block ok, progress = %"PRIu64" / %"PRIu64"\n", progress_step, progress_total);
	for (block_index = 0; block_index < block_count; block_index++){
		printf("original_data[%2"PRIu64"] = %p\n", block_index, original_data[block_index]);
	}
	for (block_index = 0; block_index < max_recovery_block; block_index++){
		printf("recovery_data[%2"PRIu64"] = %p\n", block_index, recovery_data[block_index]);
	}
}
*/

		// Recover lost input blocks
		if (par3_ctx->ecc_method & 1){	// Cauchy Reed-Solomon Codes
			rs_recover_all(par3_ctx, region_size, (int)lost_count, progress_total, progress_step);

		} else if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
			ret = leo_decode(region_size,
							(uint32_t)block_count, (uint32_t)max_recovery_block, work_count,
							original_data, recovery_data, work_data);
			if (ret != 0){
				printf("Failed to call Leopard-RS library (%d)\n", ret);
				return RET_LOGIC_ERROR;
			}

			// Restore recovered data
			buf_p = block_data;
			for (block_index = 0; block_index < block_count; block_index++){
				if ((block_list[block_index].state & (4 | 16)) == 0){	// lost input block
					memcpy(buf_p, work_data[block_index], region_size);
				}
				buf_p += region_size;
			}

		}
		if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
			progress_step += block_count * lost_count;
			time_old = time(NULL);
		}

		// Restore all input blocks
		buf_p = block_data;
		for (block_index = 0; block_index < block_count; block_index++){
			if ((block_list[block_index].state & (4 | 16)) == 0){	// This input block was not complete.
				// Check parity of recovered block to confirm that calculation was correct.
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
					printf("Parity of recovered block[%"PRIu64"] is different.\n", block_index);
					return RET_LOGIC_ERROR;
				}
			} else if ( (par3_ctx->ecc_method & 8) && (gf_size == 2) ){
				leo_region_restore(buf_p, region_size);	// Return from ALTMAP
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
						if (par3_ctx->noise_level >= 3){
							printf("Writing %zu bytes of slice[%"PRIi64"] on file[%u]:%"PRIi64" in block[%"PRIu64"]\n", io_size, slice_index, file_index, file_offset, block_index);
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
				if (chunk_size == 0){	// Unprotected Chunk Description
					// Unprotected chunk will be filled by zeros after repair.
					file_size += chunk_list[chunk_index].block;
					if (chunk_num == 1){	// When unprotected chunk is the last in the input file, set end of file.
						int file_no;
						if (par3_ctx->noise_level >= 3){
							printf("Zero padding unprotected chunk[%u] on file[%u]:%"PRIi64"\n", chunk_index, file_index, file_size);
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
						file_no = _fileno(fp);
						if (file_no < 0){
							perror("Failed to seek temporary file");
							fclose(fp);
							return RET_FILE_IO_ERROR;
						} else {
							if (_chsize_s(file_no, file_size) != 0){
								perror("Failed to resize temporary file");
								fclose(fp);
								return RET_FILE_IO_ERROR;
							}
						}
					}

				} else {	// Protected Chunk Description
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
						if (par3_ctx->noise_level >= 3){
							printf("Writing %zu bytes of chunk[%u] tail on file[%u]:%"PRIi64"\n", io_size, chunk_index, file_index, file_offset);
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
			perror("Failed to close temporary file");
			return RET_FILE_IO_ERROR;
		}
	}

	if (par3_ctx->noise_level >= 0){
		if (par3_ctx->noise_level <= 2){
			if (progress_step < progress_total)
				printf("Didn't finish progress. %"PRIu64" / %"PRIu64"\n", progress_step, progress_total);
		}
		clock_now = clock() - clock_now;
		printf("done in %.1f seconds.\n", (double)clock_now / CLOCKS_PER_SEC);
	}

	// Release some allocated memory
	free(par3_ctx->recv_id_list);
	par3_ctx->recv_id_list = NULL;
	if (par3_ctx->matrix){
		free(par3_ctx->matrix);
		par3_ctx->matrix = NULL;
	}

	return 0;
}

// At this time, interleaving is adapted only for FFT based Reed-Solomon Codes.
// When there are multiple cohorts, it recovers lost blocks in each cohort.
// This keeps one cohort's all input blocks and recovery blocks partially by spliting every block.
int recover_lost_block_cohort(PAR3_CTX *par3_ctx, char *temp_path)
{
	void *gf_table, *matrix;
	char *name_prev, *file_name;
	uint8_t buf_tail[40];
	uint8_t *block_data, *buf_p;
	uint8_t gf_size;
	uint8_t *packet_checksum;
	int galois_poly;
	int ret;
	int progress_old, progress_now;
	uint32_t split_count;
	uint32_t file_count, file_index, file_prev;
	uint32_t chunk_index, chunk_num;
	uint32_t cohort_count, cohort_index;
	uint32_t lost_index, *lost_id;
	uint32_t *lost_list, *recv_list;
	size_t io_size;
	int64_t slice_index, file_offset;
	uint64_t block_index;
	uint64_t block_size, block_count;
	uint64_t block_count2, max_recovery_block2;
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
	FILE *fp_read, *fp_write;
	time_t time_old, time_now;
	clock_t clock_now;

	// For Leopard-RS library
	uint32_t work_count;
	uint8_t **original_data = NULL, **recovery_data = NULL, **work_data = NULL;

	file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	gf_size = par3_ctx->gf_size;
	galois_poly = par3_ctx->galois_poly;
	gf_table = par3_ctx->galois_table;
	matrix = par3_ctx->matrix;
	lost_id = par3_ctx->recv_id_list;
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;
	chunk_list = par3_ctx->chunk_list;
	file_list = par3_ctx->input_file_list;
	packet_list = par3_ctx->recv_packet_list;
	packet_count = par3_ctx->recv_packet_count;
	packet_checksum = par3_ctx->matrix_packet + par3_ctx->matrix_packet_offset + 8;

	// Set count for each cohort
	cohort_count = (uint32_t)(par3_ctx->interleave) + 1;	// Minimum value is 2.
	block_count2 = (block_count + cohort_count - 1) / cohort_count;	// round up
	max_recovery_block2 = par3_ctx->max_recovery_block / cohort_count;
	lost_list = par3_ctx->lost_list;	// This was set at aggregate_block_cohort().
	recv_list = lost_list + cohort_count;
	//printf("cohort_count = %u, block_count2 = %"PRIu64", max_recovery_block2 = %"PRIu64"\n", cohort_count, block_count2, max_recovery_block2);
	//for (cohort_index = 0; cohort_index < cohort_count; cohort_index++){
	//	printf("lost_count2 = %u, recovery_block_count2 = %u\n", lost_list[cohort_index], recv_list[cohort_index]);
	//}

	// Set required memory size at first
	ret = leo_init();	// Initialize Leopard-RS library.
	if (ret != 0){
		printf("Failed to initialize Leopard-RS library (%d)\n", ret);
		return RET_LOGIC_ERROR;
	}
	work_count = leo_decode_work_count((uint32_t)block_count2, (uint32_t)max_recovery_block2);
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
			printf("\nSplit block to %u pieces of %"PRIu64" bytes.\n", split_count, split_size);
		}
	} else {
		split_count = 1;
		split_size = block_size;
	}

	// Allocate memory to keep all splitted blocks.
	// Leopard-RS requires alignment of 64 bytes.
	// At reading time, it stores using recovery blocks in place of lost input blocks.
	// Recovered lost blocks are stored in work buffer.
	// So, it will write back recovered data from there.
	region_size = (split_size + 4 + 63) & ~63;
	alloc_size = region_size * (block_count2 + work_count);
	if (alloc_size < block_size)
		alloc_size = block_size;	// This buffer size must be enough large to copy a slice.
	if (par3_ctx->noise_level >= 2){
		printf("\nAligned size of block data = %"PRIu64"\n", region_size);
		printf("Allocated memory size = %"PRIu64" * (%"PRIu64" + %u) = %"PRIu64"\n", region_size, block_count2, work_count, alloc_size);
	}
	block_data = malloc(alloc_size);
	if (block_data == NULL){
		perror("Failed to allocate memory for block data");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->block_data = block_data;

	// List of pointer
	original_data = malloc(sizeof(block_data) * (block_count2 + max_recovery_block2 + work_count));
	if (original_data == NULL){
		perror("Failed to allocate memory for Leopard-RS");
		return RET_MEMORY_ERROR;
	}
	recovery_data = original_data + block_count2;
	buf_p = block_data + region_size * block_count2;
	work_data = recovery_data + max_recovery_block2;
	for (block_index = 0; block_index < work_count; block_index++){
		work_data[block_index] = buf_p;
		buf_p += region_size;
	}
	par3_ctx->matrix = original_data;	// Release this later

	// Base name of temporary file
	sprintf(temp_path, "par3_%02X%02X%02X%02X%02X%02X%02X%02X_",
			par3_ctx->set_id[0], par3_ctx->set_id[1], par3_ctx->set_id[2], par3_ctx->set_id[3],
			par3_ctx->set_id[4], par3_ctx->set_id[5], par3_ctx->set_id[6], par3_ctx->set_id[7]);

	if (par3_ctx->noise_level >= 0){
		printf("\nRecovering lost input blocks:\n");
		progress_total = 0;
		if (par3_ctx->noise_level <= 1){
			for (cohort_index = 0; cohort_index < cohort_count; cohort_index++){
				if (lost_list[cohort_index] > recv_list[cohort_index])
					continue;
				if (lost_list[cohort_index] == 0){
					// block_count2 = Number of input block (read & write)
					progress_total += block_count2;
				} else {
					// block_count2 = Number of input block (read)
					// lost_count2 = Number of using recovery block (read)
					// block_count2 * lost_count2 = Number of multiplication
					// block_count2 = Number of input block (write)
					progress_total += block_count2 * lost_list[cohort_index] + block_count2 * 2 + lost_list[cohort_index];
				}
			}
			progress_total *= split_count;
		}
		progress_step = 0;
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}

	fp_read = NULL;
	name_prev = NULL;
	fp_write = NULL;
	file_prev = 0xFFFFFFFF;
	// Process each cohort
	for (cohort_index = 0; cohort_index < cohort_count; cohort_index++){
		if (lost_list[cohort_index] > recv_list[cohort_index]){	// Cannot recover blocks in this cohort.
			//printf("cohort[%u] : lost = %u, recovery = %u\n", cohort_index, lost_list[cohort_index], recv_list[cohort_index]);
			continue;
		}
		if (lost_list[cohort_index] == 0){	// No need to recover blocks in this cohort.
			if ( (cohort_count < 10) && (par3_ctx->noise_level >= 1) ){
				printf("cohort[%u] : no lost\n", cohort_index);
			}

			// Restore missing or damaged files by copying all input blocks
			buf_p = block_data;
			for (block_index = cohort_index; block_index < block_count; block_index += cohort_count){
				slice_index = block_list[block_index].slice;
				while (slice_index != -1){
					file_index = slice_list[slice_index].file;
					// If belong file is missing or damaged.
					if ( ((file_list[file_index].state & 3) != 0) && ((file_list[file_index].state & 4) == 0) ){
						// Read slice data from another file.
						file_name = slice_list[slice_index].find_name;
						file_offset = slice_list[slice_index].find_offset;
						io_size = slice_list[slice_index].size;
						if (par3_ctx->noise_level >= 3){
							printf("Reading %zu bytes of slice[%"PRIi64"] for input block[%"PRIu64"]\n", io_size, slice_index, block_index);
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
						if (fread(buf_p, 1, io_size, fp_read) != io_size){
							perror("Failed to read slice on Input File");
							fclose(fp_read);
							if (fp_write != NULL)
								fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}

						// Write slice data on temporary file.
						file_offset = slice_list[slice_index].offset;
						if (par3_ctx->noise_level >= 3){
							printf("Writing %zu bytes of slice[%"PRIi64"] on file[%u]\n", io_size, slice_index, file_index);
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
								fclose(fp_read);
								return RET_FILE_IO_ERROR;
							}
							file_prev = file_index;
						}
						if (_fseeki64(fp_write, file_offset, SEEK_SET) != 0){
							perror("Failed to seek temporary file");
							fclose(fp_read);
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}
						if (fwrite(buf_p, 1, io_size, fp_write) != io_size){
							perror("Failed to write slice on temporary file");
							fclose(fp_read);
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}
					}

					// Goto next slice
					slice_index = slice_list[slice_index].next;
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
			}
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
				// When the last input block doesn't exist in this cohort.
				if (block_index < block_count2 * cohort_count){
					progress_step++;
				}
			}
			continue;
		}

		if ( (cohort_count < 10) && (par3_ctx->noise_level >= 1) ){
			printf("cohort[%u] : lost = %u, recovery = %u\n", cohort_index, lost_list[cohort_index], recv_list[cohort_index]);
		}
		for (split_offset = 0; split_offset < block_size; split_offset += split_size){
			//printf("cohort_index = %u, split_offset = %"PRIu64"\n", cohort_index, split_offset);
			buf_p = block_data;	// Starting position of input blocks
			lost_index = 0;

			// Close writing file, because it will read many times and won't write for a while.
			if (fp_write != NULL){
				if (fclose(fp_write) != 0){
					perror("Failed to close temporary file");
					if (fp_read != NULL)
						fclose(fp_read);
					return RET_FILE_IO_ERROR;
				}
				fp_write = NULL;
			}

			// Store available input blocks on memory
			for (block_index = cohort_index; block_index < block_count; block_index += cohort_count){
				original_data[block_index / cohort_count] = buf_p;	// At first, set position of block data.
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
						printf("Mapping information for block[%"PRIu64"] is wrong.\n", block_index);
						if (fp_read != NULL)
							fclose(fp_read);
						return RET_LOGIC_ERROR;
					}

					// Read a part of slice from a file.
					file_name = slice_list[slice_index].find_name;
					file_offset = slice_list[slice_index].find_offset + split_offset;
					io_size = part_size;
					if (par3_ctx->noise_level >= 3){
						printf("Reading %zu bytes of slice[%"PRIi64"] for input block[%"PRIu64"]\n", io_size, slice_index, block_index);
					}
					if ( (fp_read == NULL) || (file_name != name_prev) ){
						if (fp_read != NULL){	// Close previous input file.
							fclose(fp_read);
							fp_read = NULL;
						}
						fp_read = fopen(file_name, "rb");
						if (fp_read == NULL){
							perror("Failed to open Input File");
							return RET_FILE_IO_ERROR;
						}
						name_prev = file_name;
					}
					if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
						perror("Failed to seek Input File");
						fclose(fp_read);
						return RET_FILE_IO_ERROR;
					}
					if (fread(buf_p, 1, io_size, fp_read) != io_size){
						perror("Failed to read slice on Input File");
						fclose(fp_read);
						return RET_FILE_IO_ERROR;
					}

				// All tail data is available. (one tail or packed tails)
				} else if ( (data_size > split_offset) && (block_list[block_index].state & 16) ){
					if (par3_ctx->noise_level >= 3){
						printf("Reading %"PRIu64" bytes for input block[%"PRIu64"]\n", part_size, block_index);
					}
					tail_offset = split_offset;
					while (tail_offset < split_offset + part_size){	// Read tails until data end.
						slice_index = block_list[block_index].slice;
						while (slice_index != -1){
							//printf("block = %d, size = %"PRIu64", offset = %"PRIu64", slice = %"PRIi64"\n", block_index, data_size, tail_offset, slice_index);
							// Even when chunk tails are overlaped, it will find tail slice of next position.
							if ( (slice_list[slice_index].tail_offset + slice_list[slice_index].size > tail_offset)
									&& (slice_list[slice_index].tail_offset <= tail_offset) ){
								break;
							}
							slice_index = slice_list[slice_index].next;
						}
						if (slice_index == -1){	// When there is no valid slice.
							printf("Mapping information for block[%"PRIu64"] is wrong.\n", block_index);
							if (fp_read != NULL)
								fclose(fp_read);
							return RET_LOGIC_ERROR;
						}

						// Read one slice from a file.
						tail_gap = tail_offset - slice_list[slice_index].tail_offset;	// This tail slice may start before tail_offset.
						file_name = slice_list[slice_index].find_name;
						file_offset = slice_list[slice_index].find_offset + tail_gap;
						io_size = slice_list[slice_index].size - tail_gap;
						if (io_size > part_size)
							io_size = part_size;
						if ( (fp_read == NULL) || (file_name != name_prev) ){
							if (fp_read != NULL){	// Close previous input file.
								fclose(fp_read);
								fp_read = NULL;
							}
							fp_read = fopen(file_name, "rb");
							if (fp_read == NULL){
								perror("Failed to open Input File");
								return RET_FILE_IO_ERROR;
							}
							name_prev = file_name;
						}
						if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
							perror("Failed to seek Input File");
							fclose(fp_read);
							return RET_FILE_IO_ERROR;
						}
						if (fread(buf_p + tail_offset - split_offset, 1, io_size, fp_read) != io_size){
							perror("Failed to read tail slice on Input File");
							fclose(fp_read);
							return RET_FILE_IO_ERROR;
						}
						tail_offset += io_size;
					}

				} else {	// The input block was lost, or empty space in tail block.
					if (block_list[block_index].state & 16){
						// Zero fill partial input block
						memset(buf_p, 0, region_size);
					} else {	// Set index of this lost block
						original_data[block_index / cohort_count] = NULL;	// Erase address
						// Using recovery blocks will be stored in place of lost input blocks.
						lost_id[lost_index] = (uint32_t)(block_index / cohort_count);
						lost_index++;
					}
					data_size = 0;	// No need to calculate parity.
				}

				if (data_size > split_offset){	// When there is slice data to process.
					memset(buf_p + part_size, 0, region_size - part_size);	// Zero fill rest bytes
					// No need to calculate CRC of reading block, because it will check recovered block later.

					if (gf_size == 2){
						leo_region_create_parity(buf_p, region_size);
					} else {
						region_create_parity(buf_p, region_size);
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

			// When the last input block doesn't exist in this cohort, zero fill it.
			if (block_index < block_count2 * cohort_count){
				//printf("zero fill %"PRIu64", block_count2 * cohort_count = %"PRIu64"\n", block_index, block_count2 * cohort_count);
				memset(buf_p, 0, region_size);
				original_data[block_index / cohort_count] = buf_p;
				if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
					progress_step++;
				}
			}
			//printf("\n read input block ok, lost_index = %u, progress = %"PRIu64" / %"PRIu64"\n", lost_index, progress_step, progress_total);

			// At first, clear position of recovery block.
			for (block_index = 0; block_index < max_recovery_block2; block_index++){
				recovery_data[block_index] = NULL;
			}
			lost_index = 0;

			// Read using recovery blocks
			part_size = block_size - split_offset;
			if (part_size > split_size)
				part_size = split_size;
			io_size = part_size;
			// Search packet for the recovery block
			for (packet_index = 0; packet_index < packet_count; packet_index++){
				if (memcmp(packet_list[packet_index].matrix, packet_checksum, 16) != 0)
					continue;	// Search only Recovery Data Packets belong to using Matrix Packet

				block_index = packet_list[packet_index].index;	// Index of the recovery block
				if (block_index % cohort_count != cohort_index)
					continue;	// Ignore useless recovery block in other cohorts.

				//printf("lost_index = %u, recovery block = %"PRIu64" \n", lost_index, block_index);
				buf_p = block_data + region_size * lost_id[lost_index];	// Address of the recovery block
				// Set position of lost input block = address of using recovery block
				recovery_data[block_index / cohort_count] = buf_p;
				lost_index++;

				// Read one Recovery Data Packet from a recovery file.
				file_name = packet_list[packet_index].name;
				file_offset = packet_list[packet_index].offset + 48 + 40 + split_offset;	// offset of the recovery block data
				if (par3_ctx->noise_level >= 3){
					printf("Reading Recovery Data[%"PRIu64"] for recovery block[%"PRIu64"]\n", packet_index, block_index);
				}
				if ( (fp_read == NULL) || (file_name != name_prev) ){
					if (fp_read != NULL){	// Close previous recovery file.
						fclose(fp_read);
						fp_read = NULL;
					}
					fp_read = fopen(file_name, "rb");
					if (fp_read == NULL){
						perror("Failed to open recovery file");
						return RET_FILE_IO_ERROR;
					}
					name_prev = file_name;
				}
				if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
					perror("Failed to seek recovery file");
					fclose(fp_read);
					return RET_FILE_IO_ERROR;
				}
				if (fread(buf_p, 1, io_size, fp_read) != io_size){
					perror("Failed to read recovery data on recovery file");
					fclose(fp_read);
					return RET_FILE_IO_ERROR;
				}
				memset(buf_p + part_size, 0, region_size - part_size);	// Zero fill rest bytes

				if (gf_size == 2){
					leo_region_create_parity(buf_p, region_size);
				} else {
					region_create_parity(buf_p, region_size);
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

				// Exit loop, when it read enough recovery blocks.
				if (lost_index == lost_list[cohort_index])
					break;
			}

			// Close recovery file, because next reading will be Input File.
			if (fp_read != NULL){
				if (fclose(fp_read) != 0){
					perror("Failed to close recovery file");
					return RET_FILE_IO_ERROR;
				}
				fp_read = NULL;
			}

/*
printf("\n read recovery block ok, lost_index = %u, progress = %"PRIu64" / %"PRIu64"\n", lost_index, progress_step, progress_total);

for (block_index = 0; block_index < block_count2; block_index++){
	printf("original_data[%2"PRIu64"] = %p\n", block_index, original_data[block_index]);
}
for (block_index = 0; block_index < max_recovery_block2; block_index++){
	printf("recovery_data[%2"PRIu64"] = %p\n", block_index, recovery_data[block_index]);
}
for (block_index = 0; block_index < work_count; block_index++){
	printf("work_data[%2"PRIu64"] = %p\n", block_index, work_data[block_index]);
}

{	// for debug
FILE *fp2;
fp2 = fopen("after_read.bin", "wb");
fwrite(block_data, 1, region_size * (block_count2 + work_count), fp2);
fclose(fp2);
}
*/

			// Recover lost input blocks
			ret = leo_decode(region_size,
							(uint32_t)block_count2, (uint32_t)max_recovery_block2, work_count,
							original_data, recovery_data, work_data);
			if (ret != 0){
				printf("Failed to call Leopard-RS library (%d)\n", ret);
				return RET_LOGIC_ERROR;
			}
			//printf("\n decode ok, progress = %"PRIu64" / %"PRIu64"\n", progress_step, progress_total);

			// Restore recovered data
			buf_p = block_data;
			for (block_index = 0; block_index < block_count2; block_index++){
				if (original_data[block_index] == NULL){	// lost input block
					memcpy(buf_p, work_data[block_index], region_size);
				}
				buf_p += region_size;
			}

			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
				progress_step += block_count2 * lost_index;
				time_old = time(NULL);
			}

/*
{	// for debug
FILE *fp2;
fp2 = fopen("after_recover.bin", "wb");
fwrite(block_data, 1, region_size * (block_count2 + work_count), fp2);
fclose(fp2);
}
printf("\n recover ok, progress = %"PRIu64" / %"PRIu64"\n", progress_step, progress_total);
*/

			// Restore all input blocks
			buf_p = block_data;
			for (block_index = cohort_index; block_index < block_count; block_index += cohort_count){
				if ((block_list[block_index].state & (4 | 16)) == 0){	// This input block was not complete.
					// Check parity of recovered block to confirm that calculation was correct.
					if (gf_size == 2){
						ret = leo_region_check_parity(buf_p, region_size);
					} else {
						ret = region_check_parity(buf_p, region_size);
					}
					if (ret != 0){
						printf("Parity of recovered block[%"PRIu64"] is different.\n", block_index);
						return RET_LOGIC_ERROR;
					}
				} else if (gf_size == 2){
					leo_region_restore(buf_p, region_size);	// Return from ALTMAP
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
							if (par3_ctx->noise_level >= 3){
								printf("Writing %zu bytes of slice[%"PRIi64"] on file[%u]:%"PRIi64" in block[%"PRIu64"]\n", io_size, slice_index, file_index, file_offset, block_index);
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
							if (fwrite(buf_p + tail_gap, 1, io_size, fp_write) != io_size){
								perror("Failed to write slice on temporary file");
								fclose(fp_write);
								return RET_FILE_IO_ERROR;
							}
						}
					}

					// Goto next slice
					slice_index = slice_list[slice_index].next;
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
			if ( (par3_ctx->noise_level >= 0) && (par3_ctx->noise_level <= 2) ){
				// When the last input block doesn't exist in this cohort.
				if (block_index < block_count2 * cohort_count){
					progress_step++;
				}
			}
			//printf("\n restore ok, progress = %"PRIu64" / %"PRIu64"\n", progress_step, progress_total);
		}
	}

	// Close reading file
	if (fp_read != NULL){
		if (fclose(fp_read) != 0){
			perror("Failed to close file");
			if (fp_write != NULL)
				fclose(fp_write);
			return RET_FILE_IO_ERROR;
		}
		fp_read = NULL;
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
				chunk_size = chunk_list[chunk_index].size;
				if (chunk_size == 0){	// Unprotected Chunk Description
					// Unprotected chunk will be filled by zeros after repair.
					file_size += chunk_list[chunk_index].block;
					if (chunk_num == 1){	// When unprotected chunk is the last in the input file, set end of file.
						int file_no;
						if (par3_ctx->noise_level >= 3){
							printf("Zero padding unprotected chunk[%u] on file[%u]:%"PRIi64"\n", chunk_index, file_index, file_size);
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
						file_no = _fileno(fp_write);
						if (file_no < 0){
							perror("Failed to seek temporary file");
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						} else {
							if (_chsize_s(file_no, file_size) != 0){
								perror("Failed to resize temporary file");
								fclose(fp_write);
								return RET_FILE_IO_ERROR;
							}
						}
					}

				} else {	// Protected Chunk Description
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
						if (par3_ctx->noise_level >= 3){
							printf("Writing %zu bytes of chunk[%u] tail on file[%u]:%"PRIi64"\n", io_size, chunk_index, file_index, file_offset);
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
						if (fwrite(buf_tail, 1, io_size, fp_write) != io_size){
							perror("Failed to write tiny slice on temporary file");
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}
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
			perror("Failed to close temporary file");
			return RET_FILE_IO_ERROR;
		}
	}

	if (par3_ctx->noise_level >= 0){
		if (par3_ctx->noise_level <= 2){
			if (progress_step < progress_total)
				printf("Didn't finish progress. %"PRIu64" / %"PRIu64"\n", progress_step, progress_total);
		}
		clock_now = clock() - clock_now;
		printf("done in %.1f seconds.\n", (double)clock_now / CLOCKS_PER_SEC);
	}

	// Release some allocated memory
	free(par3_ctx->recv_id_list);
	par3_ctx->recv_id_list = NULL;
	if (par3_ctx->matrix){
		free(par3_ctx->matrix);
		par3_ctx->matrix = NULL;
	}

	return 0;
}

