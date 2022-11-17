// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "common.h"


// Try Index File
void try_index_file(PAR3_CTX *par3_ctx)
{
	uint64_t file_size;

	file_size = 0;

	// Creator Packet
	file_size += par3_ctx->creator_packet_size;

	// Start Packet
	file_size += par3_ctx->start_packet_size;

	// Matrix Packet
	file_size += par3_ctx->matrix_packet_size;

	// File Packet
	file_size += par3_ctx->file_packet_size;

	// Directory Packet
	file_size += par3_ctx->dir_packet_size;

	// Root Packet
	file_size += par3_ctx->root_packet_size;

	// External Data Packet
	file_size += par3_ctx->ext_data_packet_size;

	// File System Specific Packets
	file_size += par3_ctx->file_system_packet_size;

	// Comment Packet
	file_size += par3_ctx->comment_packet_size;

	if (par3_ctx->noise_level >= -1)
		printf("Size of index file = %I64u, %s\n", file_size, offset_file_name(par3_ctx->par_filename));
}


// Try how many blocks in each file, and calculate how many digits for each block count.
void calculate_digit_max(PAR3_CTX *par3_ctx,
		uint64_t block_count, uint64_t first_num,
		uint64_t *p_base_num, uint64_t *p_max_count,
		int *p_digit_num1, int *p_digit_num2)
{
	char recovery_file_scheme;
	int digit_num1, digit_num2;
	uint32_t file_count;
	uint64_t num, base_num;
	uint64_t each_start, each_count, max_count;

	recovery_file_scheme = par3_ctx->recovery_file_scheme;

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

		} else {	// Variable (base number * power of 2)
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
	num = each_start + first_num;
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

	// Return values
	*p_base_num = base_num;
	*p_max_count = max_count;
	*p_digit_num1 = digit_num1;
	*p_digit_num2 = digit_num2;
}


static void try_data_packet(PAR3_CTX *par3_ctx, char *filename, uint64_t each_start, uint64_t each_count)
{
	uint8_t *common_packet;
	uint32_t cohort_count, write_count;
	uint64_t file_size, num;
	uint64_t block_count, block_index, block_max;
	size_t write_size, write_size2;
	size_t packet_count, packet_to, packet_from;
	size_t common_packet_size, packet_size, packet_offset;
	PAR3_BLOCK_CTX *block_list;

	block_list = par3_ctx->block_list;
	common_packet = par3_ctx->common_packet;
	common_packet_size = par3_ctx->common_packet_size;

	// Set count for each cohort
	if (par3_ctx->interleave > 0){
		block_count = par3_ctx->block_count;
		cohort_count = par3_ctx->interleave + 1;
	}

	// How many repetition of common packet.
	packet_count = 0;	// reduce 1, because put 1st copy at first.
	for (num = 2; num <= each_count; num *= 2)	// log2(each_count)
		packet_count++;
	//printf("each_count = %I64u, repetition = %zu\n", each_count, packet_count);
	packet_count *= par3_ctx->common_packet_count;
	//printf("number of repeated packets = %zu\n", packet_count);

	file_size = 0;

	// Creator Packet
	file_size += par3_ctx->creator_packet_size;

	// First common packets
	file_size += common_packet_size;

	// Data Packet and repeated common packets
	packet_from = 0;
	packet_offset = 0;
	for (num = each_start; num < each_start + each_count; num++){
		// data size in the block
		if (par3_ctx->interleave == 0){
			write_size = block_list[num].size;
			write_count = 1;
		} else {	// Write multiple blocks at interleaving
			write_size = 0;
			write_count = cohort_count;
			block_index = num * cohort_count;	// Starting index of the block
			block_max = block_index + cohort_count;	// How many blocks in the volume
			if (block_max > block_count){
				block_max = block_count;
				write_count = (uint32_t)(block_max - block_index);
			}
			//printf("block_index = %I64u, block_max = %I64u\n", block_index, block_max);
			while (block_index < block_max){
				write_size += block_list[block_index].size;
				block_index++;
			}
		}
		//printf("write_size = %zu, write_count = %u\n", write_size, write_count);

		// Write packet header and data on file.
		file_size += (48 + 8) * write_count;
		file_size += write_size;

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
			file_size += write_size;
			// This offset doesn't exceed common_packet_size.
			packet_offset += write_size;
			if (packet_offset >= common_packet_size)
				packet_offset -= common_packet_size;
		}
		if (write_size2 > 0){
			//printf("write_size2 = %zu = packet_offset\n", write_size2);
			file_size += write_size2;
			// Current offset is saved.
			packet_offset = write_size2;
		}
	}

	// Comment Packet
	file_size += par3_ctx->comment_packet_size;

	if (par3_ctx->noise_level >= -1)
		printf("Size of archive file = %I64u, %s\n", file_size, offset_file_name(filename));
}

// Write PAR3 files with Data packets (input blocks)
int try_archive_file(PAR3_CTX *par3_ctx)
{
	char filename[_MAX_PATH], recovery_file_scheme;
	int digit_num1, digit_num2;
	uint32_t file_count;
	uint64_t block_count, base_num;
	uint64_t each_start, each_count, max_count;
	size_t len;

	block_count = par3_ctx->block_count;
	if (block_count == 0)
		return 0;
	recovery_file_scheme = par3_ctx->recovery_file_scheme;
	file_count = par3_ctx->recovery_file_count;

	// Remove the last ".par3" from base PAR3 filename.
	strcpy(filename, par3_ctx->par_filename);
	len = strlen(filename);
	if (strcmp(filename + len - 5, ".par3") == 0){
		len -= 5;
		filename[len] = 0;
		//printf("len = %zu, base name = %s\n", len, filename);
	}

	// Set count for each cohort
	if (par3_ctx->interleave > 0){
		block_count = (block_count + par3_ctx->interleave) / (par3_ctx->interleave + 1);	// round up
	}

	// Calculate block count and digits max.
	calculate_digit_max(par3_ctx, block_count, 0, &base_num, &max_count, &digit_num1, &digit_num2);
	if (len + 11 + digit_num1 + digit_num2 >= _MAX_PATH){	// .part#+#.par3
		printf("PAR3 filename will be too long.\n");
		return RET_FILE_IO_ERROR;
	}

	// Write each PAR3 file.
	each_start = 0;
	while (block_count > 0){
		if (file_count > 0){
			if (recovery_file_scheme == 'u'){	// Uniform
				each_count = max_count;
				if (base_num > 0){
					base_num--;
					if (base_num == 0)
						max_count--;
				}

			} else {	// Variable (base number * power of 2)
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
		try_data_packet(par3_ctx, filename, each_start, each_count);

		each_start += each_count;
		block_count -= each_count;
	}

	return 0;
}


static void try_recovery_packet(PAR3_CTX *par3_ctx, char *filename, uint64_t each_start, uint64_t each_count)
{
	uint8_t *common_packet;
	uint32_t cohort_count;
	uint64_t file_size, block_size, num;
	size_t write_size, write_size2;
	size_t packet_count, packet_to, packet_from;
	size_t common_packet_size, packet_size, packet_offset;

	block_size = par3_ctx->block_size;
	common_packet = par3_ctx->common_packet;
	common_packet_size = par3_ctx->common_packet_size;
	cohort_count = par3_ctx->interleave + 1;

	// How many repetition of common packet.
	packet_count = 0;	// reduce 1, because put 1st copy at first.
	for (num = 2; num <= each_count; num *= 2)	// log2(each_count)
		packet_count++;
	//printf("each_count = %I64u, repetition = %zu\n", each_count, packet_count);
	packet_count *= par3_ctx->common_packet_count;
	//printf("number of repeated packets = %zu\n", packet_count);

	file_size = 0;

	// Creator Packet
	file_size += par3_ctx->creator_packet_size;

	// First common packets
	file_size += common_packet_size;

	// Recovery Data Packet and repeated common packets
	packet_from = 0;
	packet_offset = 0;
	for (num = each_start; num < each_start + each_count; num++){
		// Write packet header and dummy data on file.
		// It will write recovery block later.
		file_size += (48 + 40) * cohort_count;
		file_size += block_size * cohort_count;

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
			file_size += write_size;
			// This offset doesn't exceed common_packet_size.
			packet_offset += write_size;
			if (packet_offset >= common_packet_size)
				packet_offset -= common_packet_size;
		}
		if (write_size2 > 0){
			//printf("write_size2 = %zu = packet_offset\n", write_size2);
			file_size += write_size2;
			// Current offset is saved.
			packet_offset = write_size2;
		}
	}

	// Comment Packet
	file_size += par3_ctx->comment_packet_size;

	if (par3_ctx->noise_level >= -1)
		printf("Size of recovery file = %I64u, %s\n", file_size, offset_file_name(filename));
}

// Write PAR3 files with Recovery Data packets (recovery blocks are not written yet)
int try_recovery_file(PAR3_CTX *par3_ctx)
{
	char filename[_MAX_PATH], recovery_file_scheme;
	int digit_num1, digit_num2;
	uint32_t file_count;
	uint64_t block_count, base_num, first_num;
	uint64_t each_start, each_count, max_count;
	size_t len;

	block_count = par3_ctx->recovery_block_count;
	if (block_count == 0)
		return 0;
	recovery_file_scheme = par3_ctx->recovery_file_scheme;
	file_count = par3_ctx->recovery_file_count;
	first_num = par3_ctx->first_recovery_block;

	// Remove the last ".par3" from base PAR3 filename.
	strcpy(filename, par3_ctx->par_filename);
	len = strlen(filename);
	if (strcmp(filename + len - 5, ".par3") == 0){
		len -= 5;
		filename[len] = 0;
		//printf("len = %zu, base name = %s\n", len, filename);
	}

	// Set count for each cohort
	if (par3_ctx->interleave > 0){
		block_count = (block_count + par3_ctx->interleave) / (par3_ctx->interleave + 1);	// round up
	}

	// Calculate block count and digits max.
	calculate_digit_max(par3_ctx, block_count, first_num, &base_num, &max_count, &digit_num1, &digit_num2);
	if (len + 10 + digit_num1 + digit_num2 >= _MAX_PATH){	// .vol#+#.par3
		printf("PAR3 filename will be too long.\n");
		return RET_FILE_IO_ERROR;
	}

	// Write each PAR3 file.
	each_start = first_num;
	while (block_count > 0){
		if (file_count > 0){
			if (recovery_file_scheme == 'u'){	// Uniform
				each_count = max_count;
				if (base_num > 0){
					base_num--;
					if (base_num == 0)
						max_count--;
				}

			} else {	// Variable (base number * power of 2)
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

		sprintf(filename + len, ".vol%0*I64u+%0*I64u.par3", digit_num1, each_start, digit_num2, each_count);
		try_recovery_packet(par3_ctx, filename, each_start, each_count);

		each_start += each_count;
		block_count -= each_count;
	}

	return 0;
}

// Erase created PAR3 files, when error occured.
void remove_recovery_file(PAR3_CTX *par3_ctx)
{
	char filename[_MAX_PATH], recovery_file_scheme;
	int digit_num1, digit_num2;
	uint32_t file_count;
	uint64_t block_count, base_num, first_num;
	uint64_t each_start, each_count, max_count;
	size_t len;

/*
	// Do you remove Index file, too ?
	if (remove(par3_ctx->par_filename) != 0){
		if (errno != ENOENT)
			return;	// Failed to remove Index file
	}
*/

	block_count = par3_ctx->recovery_block_count;
	recovery_file_scheme = par3_ctx->recovery_file_scheme;
	file_count = par3_ctx->recovery_file_count;
	first_num = par3_ctx->first_recovery_block;

	// Remove the last ".par3" from base PAR3 filename.
	strcpy(filename, par3_ctx->par_filename);
	len = strlen(filename);
	if (strcmp(filename + len - 5, ".par3") == 0){
		len -= 5;
		filename[len] = 0;
		//printf("len = %zu, base name = %s\n", len, filename);
	}

	// Set count for each cohort
	if (par3_ctx->interleave > 0){
		block_count = (block_count + par3_ctx->interleave) / (par3_ctx->interleave + 1);	// round up
	}

	// Calculate block count and digits max.
	calculate_digit_max(par3_ctx, block_count, first_num, &base_num, &max_count, &digit_num1, &digit_num2);

	// Remove each PAR3 file.
	each_start = first_num;
	while (block_count > 0){
		if (file_count > 0){
			if (recovery_file_scheme == 'u'){	// Uniform
				each_count = max_count;
				if (base_num > 0){
					base_num--;
					if (base_num == 0)
						max_count--;
				}

			} else {	// Variable (base number * power of 2)
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

		sprintf(filename + len, ".vol%0*I64u+%0*I64u.par3", digit_num1, each_start, digit_num2, each_count);
		if (remove(filename) != 0){
			if (errno != ENOENT)
				return;	// Failed to remove PAR3 file
		}

		each_start += each_count;
		block_count -= each_count;
	}
}

