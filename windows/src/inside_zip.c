// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "inside.h"
#include "common.h"


#define ZIP_SEARCH_SIZE	1024

// Check ZIP file and return total size of footer sections.
// format_type : 0 = Unknown, 1 = PAR3, 2 = ZIP, 3 = 7-Zip
// copy_size   : 0 = 7-Zip, 22 or 98 or more = ZIP
int check_outside_format(PAR3_CTX *par3_ctx, int *format_type, uint32_t *copy_size)
{
	unsigned char buf[ZIP_SEARCH_SIZE];
	uint32_t byte4;
	int64_t byte8, file_size, read_size, offset, footer_size;
	FILE *fp;

	*format_type = 0;
	file_size = par3_ctx->total_file_size;

	//printf("ZIP filename = \"%s\"\n", par3_ctx->par_filename);
	fp = fopen(par3_ctx->par_filename, "rb");
	if (fp == NULL){
		perror("Failed to open ZIP file");
		return RET_FILE_IO_ERROR;
	}

	// Check file format
	// 7z =  Signature of starting 6-bytes
	// zip = local file header signature (starting 4-bytes) and
	//       end of central directory record (last 22-bytes)
	footer_size = 0;
	byte8 = fread(buf, 1, 32, fp);
	if (byte8 != 32){
		perror("Failed to read ZIP file");
		fclose(fp);
		return RET_FILE_IO_ERROR;
	}
	if (((uint32_t *)buf)[0] == 0x04034b50){	// ZIP archive
		*format_type = 2;

		// Seek to end of file
		if (_fseeki64(fp, 0, SEEK_END) != 0){
			perror("Failed to seek ZIP file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}

		// Read some bytes from the last of ZIP file
		read_size = ZIP_SEARCH_SIZE;
		if (read_size > file_size)
			read_size = file_size;
		if (_fseeki64(fp, - read_size, SEEK_END) != 0){
			perror("Failed to seek ZIP file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		byte8 = fread(buf, 1, read_size, fp);
		if (byte8 != read_size){
			perror("Failed to read ZIP file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}

		// Search ZIP signature from the last
		offset = read_size - 22;
		while (offset >= 0){
			if (((uint32_t *)(buf + offset))[0] == 0x06054b50){	// End of central directory record
				memcpy(&byte4, buf + offset + 12, 4);	// size of the central directory
				byte8 = byte4;
				memcpy(&byte4, buf + offset + 16, 4);	// offset of start of central directory
				byte8 += byte4;
				if (byte8 + read_size - offset == file_size){
					footer_size = read_size - offset;
					break;
				}
			} else if (((uint32_t *)(buf + offset))[0] == 0x06064b50){	// Zip64 end of central directory record
				memcpy(&byte8, buf + offset + 40, 8);		// size of the central directory
				memcpy(&footer_size, buf + offset + 48, 8);	// // offset of start of central directory
				if (byte8 + footer_size + read_size - offset == file_size){
					footer_size = read_size - offset;
					break;
				}
			}

			offset--;
		}
		if (footer_size == 0){	// Not found
			fclose(fp);
			printf("Invalid ZIP file format\n");
			return RET_LOGIC_ERROR;
		}

	} else if ( (((uint16_t *)buf)[0] == 0x7A37) && (((uint32_t *)(buf + 2))[0] == 0x1C27AFBC) ){	// 7-Zip archive
		*format_type = 3;

		// Check size in Start Header
		memcpy(&offset, buf + 12, 8);
		memcpy(&byte8, buf + 20, 8);
		if (32 + offset + byte8 != file_size){
			fclose(fp);
			printf("Invalid 7-Zip file format\n");
			return RET_LOGIC_ERROR;
		}

	} else {	// Unknown format
		fclose(fp);
		printf("Unknown file format\n");
		return RET_LOGIC_ERROR;
	}

	if (fclose(fp) != 0){
		perror("Failed to close ZIP file");
		return - RET_FILE_IO_ERROR;
	}

	*copy_size = (uint32_t)footer_size;
	return 0;
}

// It appends PAR3 packets after a ZIP file.
// It appends the last three ZIP sections after PAR3 packets, too.
// Zip64 end of central directory record, Zip64 end of central directory locator, End of central directory record
// [ Original ZIP file ] [ PAR3 packets ] [ Duplicated ZIP section ]
uint64_t inside_zip_size(PAR3_CTX *par3_ctx,
		uint64_t block_size,	// Block size to calculate total packet size
		uint32_t footer_size,	// Copy size after appending recovery data
		uint64_t *block_count,
		uint64_t *recv_block_count)
{
	int repeat_count, redundancy_percent;
	int footer_block_count, tail_block_count;
	uint64_t i;
	uint64_t input_block_count, data_block_count, recovery_block_count;
	uint64_t data_size, data_tail_size, footer_tail_size;
	uint64_t common_packet_size, total_packet_size;
	uint64_t start_packet_size, ext_data_packet_size;
	uint64_t matrix_packet_size, recv_data_packet_size;
	uint64_t file_packet_size,  root_packet_size;

	if (par3_ctx->redundancy_size <= 250){
		redundancy_percent = par3_ctx->redundancy_size;
	} else {
		redundancy_percent = 0;
	}

	// Because it duplicates ZIP sections, there are 3 protected chunks.
	// [ data chunk ] [ footer chunk ] [ unprotected chunk ] [ duplicated footer chunk ]
	data_size = par3_ctx->total_file_size - footer_size;
	if (par3_ctx->noise_level >= 2){
		printf("data_size = %I64d, footer_size = %d, block_size = %I64d\n", data_size, footer_size, block_size);
	}

	// How many blocks in 1st protected chunk
	tail_block_count = 0;
	data_block_count = data_size / block_size;
	data_tail_size = data_size % block_size;
	if (data_tail_size >= 40)
		tail_block_count++;

	// How many blocks in 2nd protected chunk
	footer_block_count = (int)(footer_size / block_size);
	footer_tail_size = footer_size % block_size;
	if (footer_tail_size >= 40){
		if (data_tail_size >= 40){	// Try tail packing
			if (data_tail_size + footer_tail_size <= block_size){
				// Tail packing is possible.
			} else {
				tail_block_count++;
			}
		} else {
			tail_block_count++;
		}
	}
	// Because data in 2nd chunk and 3rd chunk are identical, deduplication works.

	// Create at least 1 recovery block
	input_block_count = data_block_count + footer_block_count + tail_block_count;
	if (redundancy_percent == 0){
		recovery_block_count = 1;
	} else {
		recovery_block_count = (input_block_count * redundancy_percent + 99) / 100;	// Round up
		if (recovery_block_count < 1)
			recovery_block_count = 1;
	}

	if (par3_ctx->noise_level >= 2){
		printf("data_block = %I64d, footer_block = %d, tail_block = %d\n", data_block_count, footer_block_count, tail_block_count);
		printf("input_block_count = %I64d, recovery_block_count = %I64d\n", input_block_count, recovery_block_count);
	}

	// Creator Packet
	if (par3_ctx->noise_level >= 1){
		printf("Creator Packet size = %I64d\n", par3_ctx->creator_packet_size);
	}

	// Start Packet
	start_packet_size = 48 + 33 + 1;	// Assume GF(2^8) at first
	if (input_block_count + recovery_block_count > 256)
		start_packet_size++;	// Use GF(2^16) for many blocks
	common_packet_size = start_packet_size;
	if (par3_ctx->noise_level >= 1){
		printf("Start Packet size = %I64d\n", start_packet_size);
	}

	// External Data Packet
	// All input blocks make checksum for "PAR inside" feature.
	// Even when it packs chunk tails, it stores the block's checksum of packed tails.
	ext_data_packet_size = 48 + 8 + 24 * input_block_count;
	common_packet_size += ext_data_packet_size;
	if (par3_ctx->noise_level >= 1){
		printf("External Data Packet size = %I64d\n", ext_data_packet_size);
	}

	// Matrix Packet
	// Cauchy Matrix Packet
	matrix_packet_size = 48 + 24;
	common_packet_size += matrix_packet_size;
	if (par3_ctx->noise_level >= 1){
		printf("Cauchy Matrix Packet size = %I64d\n", matrix_packet_size);
	}

	// Recovery Data Packet
	recv_data_packet_size = 48 + 40 + block_size;
	if (par3_ctx->noise_level >= 1){
		printf("Recovery Data Packet size = %I64d\n", recv_data_packet_size);
	}

	// File Packet
	i = strlen(par3_ctx->par_filename);
	file_packet_size = 48 + 2 + i + 25;
	// Protected Chunk Description (data chunk)
	file_packet_size += 8;	// length of protected chunk
	if (data_size >= block_size)
		file_packet_size += 8;	// index of first input block holding chunk
	if (data_tail_size >= 40){
		file_packet_size += 40;
	} else {
		file_packet_size += data_tail_size;
	}
	// Protected Chunk Description (footer chunk)
	file_packet_size += 8;	// length of protected chunk
	if (footer_size >= block_size)
		file_packet_size += 8;	// index of first input block holding chunk
	if (footer_tail_size >= 40){
		file_packet_size += 40;
	} else {
		file_packet_size += footer_tail_size;
	}
	// Unprotected Chunk Description (par3 packets)
	file_packet_size += 16;
	// Protected Chunk Description (duplicated footer chunk)
	file_packet_size += 8;	// length of protected chunk
	if (footer_size >= block_size)
		file_packet_size += 8;	// index of first input block holding chunk
	if (footer_tail_size >= 40){
		file_packet_size += 40;
	} else {
		file_packet_size += footer_tail_size;
	}
	common_packet_size += file_packet_size;
	if (par3_ctx->noise_level >= 1){
		printf("File Packet size = %I64d\n", file_packet_size);
	}

	// Root Packet
	root_packet_size = 48 + 13 + 16;
	common_packet_size += root_packet_size;
	if (par3_ctx->noise_level >= 1){
		printf("Root Packet size = %I64d\n", root_packet_size);
	}

	// How many times to duplicate common packets
	// number of blocks = 1 ~ 3 : number of copies = 2
	// number of blocks = 4 ~ 7 : number of copies = 3
	// number of blocks = 8 ~ 15 : number of copies = 4
	// number of blocks = 16 ~ 31 : number of copies = 5
	// number of blocks = 32 ~ 63 : number of copies = 6
	// number of blocks = 64 ~ 127 : number of copies = 7
	// number of blocks = 128 ~ 255 : number of copies = 8
	// number of blocks = 256 ~ 511 : number of copies = 9
	// number of blocks = 512 ~ 1023 : number of copies = 10
	// number of blocks = 1024 ~ 2047 : number of copies = 11
	// number of blocks = 2048 ~ 4095 : number of copies = 12
	// number of blocks = 4096 ~ 8191 : number of copies = 13
	// number of blocks = 8192 ~ 16383 : number of copies = 14
	// number of blocks = 16384 ~ 32767 : number of copies = 15
	// number of blocks = 32768 ~ 65535 : number of copies = 16
	repeat_count = 2;
	for (i = 4; i <= recovery_block_count; i *= 2)	// log2(recovery_block_count)
		repeat_count++;
	// Limit repetition by redundancy
	// Redundancy = 0 ~ 5% : Max 4 times
	// Redundancy = 6 ~ 10% : Max "redundancy - 1" times
	// Redundancy = 11% : 11 * 100 / 111 = 9.91, Max 9 times
	// Redundancy = 20% : 20 * 100 / 120 = 16.66, Max 16 times
	if (redundancy_percent <= 5){
		if (repeat_count > 4)
			repeat_count = 4;
	} else if (redundancy_percent <= 10){
		if (repeat_count > redundancy_percent - 1)
			repeat_count = redundancy_percent - 1;
	} else if (redundancy_percent < 20){	// n * 100 / (100 + n)
		i = (redundancy_percent * 100) / (100 + redundancy_percent);
		if (repeat_count > (int)i)
			repeat_count = (int)i;
	}
	if (par3_ctx->noise_level >= 2){
		printf("repeat_count = %d\n", repeat_count);
	}

	// Calculate total size of PAR3 packets (repeated multiple times)
	total_packet_size = par3_ctx->creator_packet_size;
	total_packet_size += common_packet_size * repeat_count;
	total_packet_size += recv_data_packet_size * recovery_block_count;
	if (par3_ctx->noise_level >= 1){
		if (par3_ctx->noise_level >= 2){
			double rate;
			rate = (double)(block_size * recovery_block_count) / (double)total_packet_size;
			printf("Recovery data in unprotected chunks = %.1f%%\n", rate * 100);
		}
		printf("Common packet size = %I64d\n", common_packet_size);
		printf("Total packet size = %I64d\n\n", total_packet_size);
	}

	*block_count = input_block_count;
	*recv_block_count = recovery_block_count;
	return total_packet_size;
}

