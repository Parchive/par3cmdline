
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake3/blake3.h"
#include "libpar3.h"
#include "common.h"
#include "packet.h"


// Write Index File
int write_index_file(PAR3_CTX *par3_ctx)
{
	size_t write_size;
	FILE *fp;

	fp = fopen(par3_ctx->par_filename, "wb");
	if (fp == NULL){
		perror("Failed to open Index File");
		return RET_FILE_IO_ERROR;
	}

	// Creator Packet
	write_size = par3_ctx->creator_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->creator_packet, 1, write_size, fp) != write_size){
			perror("Failed to write Creator Packet on Index File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// Start Packet
	write_size = par3_ctx->start_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->start_packet, 1, write_size, fp) != write_size){
			perror("Failed to write Start Packet on Index File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// Matrix Packet
	write_size = par3_ctx->matrix_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->matrix_packet, 1, write_size, fp) != write_size){
			perror("Failed to write Matrix Packet on Index File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// File Packet
	write_size = par3_ctx->file_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->file_packet, 1, write_size, fp) != write_size){
			perror("Failed to write File Packet on Index File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// Directory Packet
	write_size = par3_ctx->dir_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->dir_packet, 1, write_size, fp) != write_size){
			perror("Failed to write Directory Packet on Index File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// Root Packet
	write_size = par3_ctx->root_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->root_packet, 1, write_size, fp) != write_size){
			perror("Failed to write Root Packet on Index File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// External Data Packet
	write_size = par3_ctx->ext_data_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->ext_data_packet, 1, write_size, fp) != write_size){
			perror("Failed to write External Data Packet on Index File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// Comment Packet
	write_size = par3_ctx->comment_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->comment_packet, 1, write_size, fp) != write_size){
			perror("Failed to write Comment Packet on Index File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	if (fclose(fp) != 0){
		perror("Failed to close Index File");
		return RET_FILE_IO_ERROR;
	}

	if (par3_ctx->noise_level >= -1)
		printf("Wrote index file, %s\n", offset_file_name(par3_ctx->par_filename));

	return 0;
}

/*
Redundancy of critical packets;
number of blocks = 0 ~ 1 : number of copies = 1
number of blocks = 2 ~ 3 : number of copies = 2
number of blocks = 4 ~ 7 : number of copies = 3
number of blocks = 8 ~ 15 : number of copies = 4
number of blocks = 16 ~ 31 : number of copies = 5
number of blocks = 32 ~ 63 : number of copies = 6
number of blocks = 64 ~ 127 : number of copies = 7
number of blocks = 128 ~ 255 : number of copies = 8
number of blocks = 256 ~ 511 : number of copies = 9
number of blocks = 512 ~ 1023 : number of copies = 10
number of blocks = 1024 ~ 2047 : number of copies = 11
number of blocks = 2048 ~ 4095 : number of copies = 12
number of blocks = 4096 ~ 8191 : number of copies = 13
number of blocks = 8192 ~ 16383 : number of copies = 14
number of blocks = 16384 ~ 32767 : number of copies = 15
number of blocks = 32768 ~ 65535 : number of copies = 16
*/
static int write_data_packet(PAR3_CTX *par3_ctx, char *filename, uint64_t each_start, uint64_t each_count)
{
	uint8_t *buf_p, *common_packet, packet_header[56];
	uint64_t block_size, num;
	size_t write_size, write_size2;
	size_t packet_count, packet_to, packet_from;
	size_t common_packet_size, packet_size, packet_offset;
	PAR3_MAP_CTX *map_list;
	PAR3_BLOCK_CTX *block_list;
	FILE *fp;
	blake3_hasher hasher;

	block_size = par3_ctx->block_size;
	buf_p = par3_ctx->input_block + block_size * each_start;
	map_list = par3_ctx->map_list;
	block_list = par3_ctx->block_list;
	common_packet = par3_ctx->common_packet;
	common_packet_size = par3_ctx->common_packet_size;

	// How many repetition of common packet.
	packet_count = 0;	// reduce 1, because put 1st copy at first.
	for (num = 2; num <= each_count; num *= 2)	// log2(each_count)
		packet_count++;
	//printf("each_count = %I64u, repetition = %zu\n", each_count, packet_count);
	packet_count *= par3_ctx->common_packet_count;
	//printf("number of repeated packets = %zu\n", packet_count);

	fp = fopen(filename, "wb");
	if (fp == NULL){
		perror("Failed to open Archive File");
		return RET_FILE_IO_ERROR;
	}

	// Creator Packet
	write_size = par3_ctx->creator_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->creator_packet, 1, write_size, fp) != write_size){
			perror("Failed to write Creator Packet on Archive File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// First common packets
	write_size = common_packet_size;
	if (fwrite(common_packet, 1, write_size, fp) != write_size){
		perror("Failed to write first common packets on Archive File");
		fclose(fp);
		return RET_FILE_IO_ERROR;
	}

	// Data Packet and repeated common packets
	packet_from = 0;
	packet_offset = 0;
	for (num = each_start; num < each_start + each_count; num++){
		// data size in the block
		write_size = block_list[num].size;

		// packet header
		make_packet_header(packet_header, 56 + write_size, par3_ctx->set_id, "PAR DAT\0", 0);

		// The index of the input block
		memcpy(packet_header + 48, &num, 8);

		// Calculate hash of packet here.
		blake3_hasher_init(&hasher);
		blake3_hasher_update(&hasher, packet_header + 24, 24 + 8);
		blake3_hasher_update(&hasher, buf_p, write_size);
		blake3_hasher_finalize(&hasher, packet_header + 8, 16);

		// Write packet header and data on file.
		if (fwrite(packet_header, 1, 56, fp) != 56){
			perror("Failed to write Data Packet on Archive File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fwrite(buf_p, 1, write_size, fp) != write_size){
			perror("Failed to write Data Packet on Archive File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		buf_p += block_size;

		// How many common packets to write here.
		write_size = 0;
		write_size2 = 0;
		packet_to = packet_count * (num - each_start + 1) / each_count;
		//printf("write from %zu to %zu\n", packet_from, packet_to);
		while (packet_to - packet_from > 0){
			// Read packet size of each packet from packet_offset, and add them.
			memcpy(&packet_size, common_packet + packet_offset + write_size + 24, 8);
			write_size += packet_size;
			packet_from++;
			if (packet_offset + write_size >= common_packet_size)
				break;
		}
		while (packet_to - packet_from > 0){
			// Read packet size of each packet from the first, and add them.
			memcpy(&packet_size, common_packet + write_size2 + 24, 8);
			write_size2 += packet_size;
			packet_from++;
		}

		// Write common packets
		if (write_size > 0){
			//printf("packet_offset = %zu, write_size = %zu, total = %zu\n", packet_offset, write_size, packet_offset + write_size);
			if (fwrite(common_packet + packet_offset, 1, write_size, fp) != write_size){
				perror("Failed to write repeated common packet on Archive File");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			// This offset doesn't exceed common_packet_size.
			packet_offset += write_size;
			if (packet_offset >= common_packet_size)
				packet_offset -= common_packet_size;
		}
		if (write_size2 > 0){
			//printf("write_size2 = %zu = packet_offset\n", write_size2);
			if (fwrite(common_packet, 1, write_size2, fp) != write_size2){
				perror("Failed to write repeated common packet on Archive File");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			// Current offset is saved.
			packet_offset = write_size2;
		}
	}

	// Comment Packet
	write_size = par3_ctx->comment_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->comment_packet, 1, write_size, fp) != write_size){
			perror("Failed to write Comment Packet on Archive File");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	if (fclose(fp) != 0){
		perror("Failed to close Archive File");
		return RET_FILE_IO_ERROR;
	}

	return 0;
}

// Write PAR3 files with Data packets (input blocks)
int write_archive_file(PAR3_CTX *par3_ctx)
{
	char filename[_MAX_PATH], recovery_file_scheme;
	int digit_num1, digit_num2;
	uint32_t file_count;
	uint64_t num, block_count, base_num;
	uint64_t each_start, each_count, max_count;
	size_t len;

	block_count = par3_ctx->block_count;
	if (block_count == 0)
		return 0;
	recovery_file_scheme = par3_ctx->recovery_file_scheme;

	// Remove the last ".par3" from base PAR3 filename.
	strcpy(filename, par3_ctx->par_filename);
	len = strlen(filename);
	if (strcmp(filename + len - 5, ".par3") == 0){
		len -= 5;
		filename[len] = 0;
		//printf("len = %zu, base name = %s\n", len, filename);
	}

	// Check max number of digits.
	file_count = par3_ctx->recovery_file_count;
	if (file_count > block_count)
		file_count = (uint32_t)block_count;	// Number of files cannot exceed number of blocks.
	if (file_count > 0){	// Number of input block files is same as recovery block files.
		if (recovery_file_scheme == 'u'){	// Uniform
			max_count = block_count / file_count;
			base_num = block_count % file_count;
			each_start = block_count - max_count;
			if (base_num > 0)
				max_count++;

		} else {	// Variable (multiply by 1~2)
			max_count = 1;
			for (num = 1; num < file_count; num++){
				max_count = max_count * 2 + 1;
				if (max_count >= block_count){
					file_count = (uint32_t)(num + 1);
					break;
				}
			}
			//printf("file_count = %u, (2 pow file_count) - 1 = %I64u\n", file_count, max_count);
			if (max_count < block_count){	// Multiply by 2
				base_num = (block_count + max_count - 1) / max_count;	// round up
			} else {	// Number of files is reduced.
				base_num = 1;
			}

			num = base_num;
			max_count = 0;
			each_start = 0;
			each_count = 0;
			while (block_count > 0){
				each_start += each_count;
				each_count = num;
				num *= 2;
				if (each_count > block_count)
					each_count = block_count;
				if (max_count < each_count)
					max_count = each_count;

				block_count -= each_count;
			}
		}

	} else {	// Set number of files automatically.
		if (recovery_file_scheme == 'u'){	// Uniform
			// Put all input blocks on a single file.
			max_count = block_count;
			each_start = 0;

		} else if (recovery_file_scheme == 'l'){	// Limit size
			num = (par3_ctx->max_file_size + par3_ctx->block_size - 1) / par3_ctx->block_size;
			//printf("limit = %I64u\n", num);
			base_num = 1;
			each_start = 0;
			each_count = 0;
			max_count = 0;
			while (block_count > 0){
				each_start += each_count;
				each_count = base_num;
				base_num *= 2;
				if (each_count > num)
					each_count = num;
				if (each_count > block_count)
					each_count = block_count;
				if (max_count < each_count)
					max_count = each_count;

				block_count -= each_count;
			}
			base_num = 1;

		} else {	// Power of 2
			base_num = 1;
			each_start = 0;
			each_count = 0;
			max_count = 0;
			while (block_count > 0){
				each_start += each_count;
				each_count = base_num;
				base_num *= 2;
				if (each_count > block_count)
					each_count = block_count;
				if (max_count < each_count)
					max_count = each_count;

				block_count -= each_count;
			}
			base_num = 1;
		}
	}

	// Calculate how many digits for each block count.
	//printf("max_start = %I64u, max_count = %I64u\n", each_start, max_count);
	digit_num1 = 1;
	num = each_start;
	while (num >= 10){
		num /= 10;
		digit_num1++;
	}
	digit_num2 = 1;
	num = max_count;
	while (num >= 10){
		num /= 10;
		digit_num2++;
	}
	if (len + 11 + digit_num1 + digit_num2 >= _MAX_PATH){
		printf("PAR3 filename will be too long.\n");
		return RET_FILE_IO_ERROR;
	}

	// Write each PAR3 file.
	each_start = 0;
	block_count = par3_ctx->block_count;
	while (block_count > 0){
		if (file_count > 0){
			if (recovery_file_scheme == 'u'){	// Uniform
				each_count = max_count;
				if (base_num > 0){
					base_num--;
					if (base_num == 0)
						max_count--;
				}

			} else {	// Variable (multiply by 2)
				each_count = base_num;
				base_num *= 2;
				if (each_count > block_count)
					each_count = block_count;
			}

		} else {
			if (recovery_file_scheme == 'u'){	// Uniform
				each_count = block_count;

			} else if (recovery_file_scheme == 'l'){	// Limit size
				each_count = base_num;
				base_num *= 2;
				if (each_count > max_count)
					each_count = max_count;
				if (each_count > block_count)
					each_count = block_count;

			} else {	// Power of 2
				each_count = base_num;
				base_num *= 2;
				if (each_count > block_count)
					each_count = block_count;
			}
		}

		sprintf(filename + len, ".part%0*I64u+%0*I64u.par3", digit_num1, each_start, digit_num2, each_count);
		if (write_data_packet(par3_ctx, filename, each_start, each_count) != 0){
			return RET_FILE_IO_ERROR;
		}
		if (par3_ctx->noise_level >= -1)
			printf("Wrote archive file, %s\n", offset_file_name(filename));

		each_start += each_count;
		block_count -= each_count;
	}

	return 0;
}

