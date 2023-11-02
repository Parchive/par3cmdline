// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if __linux__

#elif _WIN32

// MSVC headers
#include <io.h>

#endif

#include "libpar3.h"
#include "hash.h"
#include "inside.h"
#include "common.h"


#define ZIP_SEARCH_SIZE	1024

// Check ZIP file format and total size of footer sections
// format_type : 0 = Unknown, 1 = PAR3, 2 = ZIP, 3 = 7z
// copy_size   : 0 = 7z, 22 or 98 or more = ZIP
int check_outside_format(PAR3_CTX *par3_ctx, int *format_type, int *copy_size)
{
	uint8_t buf[ZIP_SEARCH_SIZE];
	int64_t file_size, read_size, offset;
	FILE *fp;

	*format_type = 0;
	*copy_size = 0;
	file_size = par3_ctx->total_file_size;

	//printf("ZIP filename = \"%s\"\n", par3_ctx->par_filename);
	fp = fopen(par3_ctx->par_filename, "rb");
	if (fp == NULL){
		perror("Failed to open Outside file");
		return RET_FILE_IO_ERROR;
	}

	// Check file format
	// 7z =  Signature of starting 6-bytes
	// zip = local file header signature (starting 4-bytes) and
	//       end of central directory record (last 22-bytes)
	if (fread(buf, 1, 32, fp) != 32){
		perror("Failed to read Outside file");
		fclose(fp);
		return RET_FILE_IO_ERROR;
	}
	if (((uint32_t *)buf)[0] == 0x04034b50){	// ZIP archive
		int footer_size = 0;
		int64_t ecdr_size;	// end of central directory record
		int64_t cdh_size, cdh_offset;	// central directory header
		*format_type = 2;

		// Read some bytes from the last of ZIP file
		read_size = ZIP_SEARCH_SIZE;
		if (read_size > file_size)
			read_size = file_size;
		if (_fseeki64(fp, - read_size, SEEK_END) != 0){	// Seek from end of file
			perror("Failed to seek Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fread(buf, 1, read_size, fp) != read_size){
			perror("Failed to read Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}

		// Search ZIP signature from the last
		offset = read_size - 22;
		while (offset >= 0){
			if (((uint32_t *)(buf + offset))[0] == 0x06054b50){	// End of central directory record
				ecdr_size = read_size - offset;
				cdh_size = 0;
				memcpy(&cdh_size, buf + offset + 12, 4);	// size of the central directory
				cdh_offset = 0;
				memcpy(&cdh_offset, buf + offset + 16, 4);	// offset of start of central directory
				if (cdh_offset + cdh_size + ecdr_size == file_size){
					footer_size = (int)ecdr_size;
					break;
				} else if ( (cdh_size == 0xFFFFFFFF) || (cdh_offset == 0xFFFFFFFF) ){
					// This ZIP file may be ZIP64 format.
					offset -= 19;
				} else if (cdh_offset + cdh_size + ecdr_size < file_size){
					fclose(fp);
					printf("There is additional data in ZIP file already.\n");
					return RET_LOGIC_ERROR;
				}
			} else if (((uint32_t *)(buf + offset))[0] == 0x06064b50){	// Zip64 end of central directory record
				ecdr_size = read_size - offset;
				memcpy(&cdh_size, buf + offset + 40, 8);	// size of the central directory
				memcpy(&cdh_offset, buf + offset + 48, 8);	 // offset of start of central directory
				if (cdh_offset + cdh_size + ecdr_size == file_size){
					footer_size = (int)ecdr_size;
					break;
				} else if (cdh_offset + cdh_size + ecdr_size < file_size){
					fclose(fp);
					printf("There is additional data in ZIP file already.\n");
					return RET_LOGIC_ERROR;
				}
			}

			offset--;
		}
		if (footer_size == 0){	// Not found
			fclose(fp);
			printf("Invalid ZIP file format\n");
			return RET_LOGIC_ERROR;
		}
		*copy_size = footer_size;

	} else if ( (((uint16_t *)buf)[0] == 0x7A37) && (((uint32_t *)(buf + 2))[0] == 0x1C27AFBC) ){	// 7z archive
		int64_t header_size;
		*format_type = 3;

		// Check size in Start Header
		memcpy(&offset, buf + 12, 8);		// NextHeaderOffset
		memcpy(&header_size, buf + 20, 8);	// NextHeaderSize
		if (32 + offset + header_size < file_size){
			fclose(fp);
			printf("There is additional data in 7z file already.\n");
			return RET_LOGIC_ERROR;
		} else if (32 + offset + header_size != file_size){
			fclose(fp);
			printf("Invalid 7z file format\n");
			return RET_LOGIC_ERROR;
		}

		// Check the end of archive file
		if (_fseeki64(fp, 32 + offset + header_size - 2, SEEK_SET) != 0){
			perror("Failed to seek Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fread(buf, 1, 2, fp) != 2){
			perror("Failed to read Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (((uint16_t *)buf)[0] != 0x0000){	// Property ID (0x00 = kEnd) and Size (0 bytes)
			fclose(fp);
			printf("Invalid 7z file format\n");
			return RET_LOGIC_ERROR;
		}

	} else {	// Unknown format
		fclose(fp);
		printf("Unknown file format\n");
		return RET_LOGIC_ERROR;
	}

	if (fclose(fp) != 0){
		perror("Failed to close Outside file");
		return RET_FILE_IO_ERROR;
	}

	return 0;
}


// It appends PAR3 packets after a ZIP file.
// It appends the last three ZIP sections after PAR3 packets, too.
// Zip64 end of central directory record, Zip64 end of central directory locator, End of central directory record
// [ Original ZIP file ] [ PAR3 packets ] [ Duplicated ZIP section ]
uint64_t inside_zip_size(PAR3_CTX *par3_ctx,
		uint64_t block_size,	// Block size to calculate total packet size
		int footer_size,		// Copy size after appending recovery data
		uint64_t *block_count,
		uint64_t *recv_block_count,
		int *packet_repeat_count)
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
		printf("data_size = %" PRId64 ", footer_size = %d, block_size = %" PRId64 "\n", data_size, footer_size, block_size);
	}
	// On the other hand, there are 1 protected chunk in 7-Zip.
	// [ data chunk ] [ unprotected chunk ]

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
		printf("data_block = %" PRId64 ", footer_block = %d, tail_block = %d\n", data_block_count, footer_block_count, tail_block_count);
		printf("input_block_count = %" PRId64 ", recovery_block_count = %" PRId64 "\n", input_block_count, recovery_block_count);
	}

	// Creator Packet
	if (par3_ctx->noise_level >= 1){
		printf("Creator Packet size = %" PRId64 "\n", par3_ctx->creator_packet_size);
	}

	// Start Packet
	start_packet_size = 48 + 33 + 1;	// Assume GF(2^8) at first
	if (input_block_count + recovery_block_count > 256)
		start_packet_size++;	// Use GF(2^16) for many blocks
	common_packet_size = start_packet_size;
	if (par3_ctx->noise_level >= 1){
		printf("Start Packet size = %" PRId64 "\n", start_packet_size);
	}

	// External Data Packet
	// Count full size blocks only in each protected chunk
	ext_data_packet_size = 48 + 8 + 24 * data_block_count;	// 1st chunk
	if (footer_block_count > 0)
		ext_data_packet_size += 48 + 8 + 24 * footer_block_count;	// 2nd chunk
	common_packet_size += ext_data_packet_size;
	if (par3_ctx->noise_level >= 1){
		printf("External Data Packet size = %" PRId64 "\n", ext_data_packet_size);
	}

	// Matrix Packet
	// Cauchy Matrix Packet
	matrix_packet_size = 48 + 24;
	common_packet_size += matrix_packet_size;
	if (par3_ctx->noise_level >= 1){
		printf("Cauchy Matrix Packet size = %" PRId64 "\n", matrix_packet_size);
	}

	// Recovery Data Packet
	recv_data_packet_size = 48 + 40 + block_size;
	if (par3_ctx->noise_level >= 1){
		printf("Recovery Data Packet size = %" PRId64 "\n", recv_data_packet_size);
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
	if (footer_size > 0){
		// Protected Chunk Description (footer chunk)
		file_packet_size += 8;	// length of protected chunk
		if (footer_size >= block_size)
			file_packet_size += 8;	// index of first input block holding chunk
		if (footer_tail_size >= 40){
			file_packet_size += 40;
		} else {
			file_packet_size += footer_tail_size;
		}
	}
	// Unprotected Chunk Description (par3 packets)
	file_packet_size += 16;
	if (footer_size > 0){
		// Protected Chunk Description (duplicated footer chunk)
		file_packet_size += 8;	// length of protected chunk
		if (footer_size >= block_size)
			file_packet_size += 8;	// index of first input block holding chunk
		if (footer_tail_size >= 40){
			file_packet_size += 40;
		} else {
			file_packet_size += footer_tail_size;
		}
	}
	common_packet_size += file_packet_size;
	if (par3_ctx->noise_level >= 1){
		printf("File Packet size = %" PRId64 "\n", file_packet_size);
	}

	// Root Packet
	root_packet_size = 48 + 13 + 16;
	common_packet_size += root_packet_size;
	if (par3_ctx->noise_level >= 1){
		printf("Root Packet size = %" PRId64 "\n", root_packet_size);
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
		printf("Common packet size = %" PRId64 "\n", common_packet_size);
		printf("Total packet size = %" PRId64 "\n\n", total_packet_size);
	}

	*block_count = input_block_count;
	*recv_block_count = recovery_block_count;
	*packet_repeat_count = repeat_count;
	return total_packet_size;
}


// Check ZIP file format and delete inside data
// At this time, this supports appended data only.
int delete_inside_data(PAR3_CTX *par3_ctx)
{
	uint8_t buf[ZIP_SEARCH_SIZE];
	int file_no;
	int64_t file_size, read_size, offset;
	FILE *fp;

	file_size = par3_ctx->total_file_size;

	//printf("ZIP filename = \"%s\"\n", par3_ctx->par_filename);
	fp = fopen(par3_ctx->par_filename, "r+b");
	if (fp == NULL){
		perror("Failed to open Outside file");
		return RET_FILE_IO_ERROR;
	}

	// Check file format
	// 7z =  Signature of starting 6-bytes
	// zip = local file header signature (starting 4-bytes) and
	//       end of central directory record (last 22-bytes)
	if (fread(buf, 1, 32, fp) != 32){
		perror("Failed to read Outside file");
		fclose(fp);
		return RET_FILE_IO_ERROR;
	}
	if (((uint32_t *)buf)[0] == 0x04034b50){	// ZIP archive
		int footer_size = 0;
		int64_t ecdr_size;	// end of central directory record
		int64_t cdh_size, cdh_offset;	// central directory header

		// Read some bytes from the last of ZIP file
		read_size = ZIP_SEARCH_SIZE;
		if (read_size > file_size)
			read_size = file_size;
		if (_fseeki64(fp, - read_size, SEEK_END) != 0){	// Seek from end of file
			perror("Failed to seek Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fread(buf, 1, read_size, fp) != read_size){
			perror("Failed to read Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}

		// Search ZIP signature from the last
		offset = read_size - 22;
		while (offset >= 0){
			if (((uint32_t *)(buf + offset))[0] == 0x06054b50){	// End of central directory record
				ecdr_size = read_size - offset;
				cdh_size = 0;
				memcpy(&cdh_size, buf + offset + 12, 4);	// size of the central directory
				cdh_offset = 0;
				memcpy(&cdh_offset, buf + offset + 16, 4);	// offset of start of central directory
				if (cdh_offset + cdh_size + ecdr_size == file_size){
					fclose(fp);
					printf("There isn't additional data in ZIP file yet.\n");
					return RET_LOGIC_ERROR;
				} else if ( (cdh_size == 0xFFFFFFFF) || (cdh_offset == 0xFFFFFFFF) ){
					// This ZIP file may be ZIP64 format.
					offset -= 20;	// Skip [zip64 end of central directory locator]
				} else if (cdh_offset + cdh_size + ecdr_size < file_size){
					footer_size = (int)ecdr_size;
					break;
				}
			} else if (((uint32_t *)(buf + offset))[0] == 0x06064b50){	// Zip64 end of central directory record
				ecdr_size = read_size - offset;
				memcpy(&cdh_size, buf + offset + 40, 8);	// size of the central directory
				memcpy(&cdh_offset, buf + offset + 48, 8);	 // offset of start of central directory
				if (cdh_offset + cdh_size + ecdr_size == file_size){
					fclose(fp);
					printf("There isn't additional data in ZIP file yet.\n");
					return RET_LOGIC_ERROR;
				} else if (cdh_offset + cdh_size + ecdr_size < file_size){
					footer_size = (int)ecdr_size;
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

		// Check ZIP signature at original position
		if (_fseeki64(fp, cdh_offset, SEEK_SET) != 0){
			perror("Failed to seek Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fread(buf, 1, 4, fp) != 4){
			perror("Failed to read Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (((uint32_t *)buf)[0] != 0x02014b50){	// central file header signature
			fclose(fp);
			printf("Invalid ZIP file format\n");
			return RET_LOGIC_ERROR;
		}
		if (_fseeki64(fp, cdh_offset + cdh_size, SEEK_SET) != 0){
			perror("Failed to seek Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fread(buf, 1, 4, fp) != 4){
			perror("Failed to read Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if ( (((uint32_t *)buf)[0] != 0x06054b50)	&&	// end of central directory record
				(((uint32_t *)buf)[0] != 0x02014b50) ){	// zip64 end of central directory record
			fclose(fp);
			printf("Invalid ZIP file format\n");
			return RET_LOGIC_ERROR;
		}
		if (par3_ctx->noise_level >= 0){
			printf("Original ZIP file size = %" PRId64 "\n", cdh_offset + cdh_size + ecdr_size);
		}

		// Delete appended data by resizing to the original ZIP file
		file_no = _fileno(fp);
		if (file_no < 0){
			perror("Failed to seek Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		} else {
			if (_chsize_s(file_no, cdh_offset + cdh_size + ecdr_size) != 0){
				perror("Failed to resize Outside file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
		}

	} else if ( (((uint16_t *)buf)[0] == 0x7A37) && (((uint32_t *)(buf + 2))[0] == 0x1C27AFBC) ){	// 7z archive
		int64_t header_size;

		// Check size in Start Header
		memcpy(&offset, buf + 12, 8);		// NextHeaderOffset
		memcpy(&header_size, buf + 20, 8);	// NextHeaderSize
		if (32 + offset + header_size == file_size){
			fclose(fp);
			printf("There isn't additional data in 7z file yet.\n");
			return RET_LOGIC_ERROR;
		} else if (32 + offset + header_size > file_size){
			fclose(fp);
			printf("Invalid 7z file format\n");
			return RET_LOGIC_ERROR;
		}
		if (par3_ctx->noise_level >= 0){
			printf("Original 7z file size = %" PRId64 "\n", 32 + offset + header_size);
		}

		// Check end mark at original position
		if (_fseeki64(fp, 32 + offset + header_size - 2, SEEK_SET) != 0){
			perror("Failed to seek Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (fread(buf, 1, 2, fp) != 2){
			perror("Failed to read Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		if (((uint16_t *)buf)[0] != 0x0000){	// Property ID (0x00 = kEnd) and Size (0 bytes)
			fclose(fp);
			printf("Invalid 7z file format\n");
			return RET_LOGIC_ERROR;
		}

		// Delete appended data by resizing to the original 7z file
		file_no = _fileno(fp);
		if (file_no < 0){
			perror("Failed to seek Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		} else {
			if (_chsize_s(file_no, 32 + offset + header_size) != 0){
				perror("Failed to resize Outside file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
		}

	} else {	// Unknown format
		fclose(fp);
		printf("Unknown file format\n");
		return RET_LOGIC_ERROR;
	}

	if (fclose(fp) != 0){
		perror("Failed to close ZIP file");
		return RET_FILE_IO_ERROR;
	}

	return 0;
}

// Copy complete PAR3 packets from damaged file to repaired file
int copy_inside_data(PAR3_CTX *par3_ctx, char *temp_path)
{
	uint8_t *buf, buf_hash[16];
	uint32_t chunk_num;
	uint64_t offset, chunk_offset, slice_offset, file_offset;
	uint64_t chunk_size, slice_size;
	uint64_t packet_size, total_packet_size;
	uint64_t slice_count, slice_index;
	uint64_t alloc_size, buf_size;
	PAR3_SLICE_CTX *slice_list;
	PAR3_CHUNK_CTX *chunk_p;
	FILE *fp_read, *fp_write;

	slice_count = par3_ctx->slice_count;
	slice_list = par3_ctx->slice_list;
	chunk_p = par3_ctx->chunk_list;
	chunk_num = par3_ctx->chunk_count;

	// Get range of target unprotected chunk
	offset = 0;
	chunk_offset = 0;
	if (chunk_num < 2)
		return RET_LOGIC_ERROR;
	while (chunk_num > 0){	// check all chunk descriptions
		chunk_size = chunk_p->size;
		if (chunk_size == 0){	// Unprotected Chunk Description
			chunk_size = chunk_p->block;
			chunk_offset = offset;
			break;
		} else {	// Protected Chunk Description
			offset += chunk_size;
		}
		chunk_p++;
		chunk_num--;
	}
	if (chunk_offset == 0)
		return RET_LOGIC_ERROR;
	if (par3_ctx->noise_level >= 2){
		printf("\nUnprotected Chunk: offset = %" PRId64 ", size = %" PRId64 "\n", chunk_offset, chunk_size);
	}

	// Buffer size must be larger than each packet size.
	// The minimum size is 4 KB to reduce time of file access.
	alloc_size = (chunk_size + 4095) & ~4095;
	packet_size = 0;
	if ( (par3_ctx->memory_limit != 0) && (alloc_size > par3_ctx->memory_limit) ){
		// Size of Recovery Data Packet at first
		packet_size = 48 + 40 + par3_ctx->block_size;
		if (packet_size < par3_ctx->creator_packet_size)
			packet_size = par3_ctx->creator_packet_size;
		if (packet_size < par3_ctx->comment_packet_size)
			packet_size = par3_ctx->comment_packet_size;
		if (packet_size < par3_ctx->start_packet_size)
			packet_size = par3_ctx->start_packet_size;
		if (packet_size < par3_ctx->matrix_packet_size)
			packet_size = par3_ctx->matrix_packet_size;
		if (packet_size < par3_ctx->file_packet_size)
			packet_size = par3_ctx->file_packet_size;
		if (packet_size < par3_ctx->dir_packet_size)
			packet_size = par3_ctx->dir_packet_size;
		if (packet_size < par3_ctx->root_packet_size)
			packet_size = par3_ctx->root_packet_size;
		// If packet size is larger than memory limit, use packet size.
		if (packet_size > par3_ctx->memory_limit){
			alloc_size = (packet_size + 4095) & ~4095;
		} else {
			alloc_size = par3_ctx->memory_limit;
		}
	}
	if (par3_ctx->noise_level >= 3){
		printf("alloc_size = %" PRId64 ", packet_size = %" PRId64 "\n", alloc_size, packet_size);
	}

	// Allocate buffer to keep PAR3 packet
	// To check completeness of the packet, it needs to read the entire bytes on memory.
	buf = malloc(alloc_size);
	if (buf == NULL){
		perror("Failed to allocate memory for PAR3 packet");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->work_buf = buf;

	// Search PAR3 packets in outside file
	fp_read = fopen(par3_ctx->par_filename, "rb");
	if (fp_read == NULL){
		perror("Failed to open Outside file");
		return RET_FILE_IO_ERROR;
	}
	fp_write = fopen(temp_path, "wb");
	if (fp_write == NULL){
		perror("Failed to open temporary file");
		fclose(fp_read);
		return RET_FILE_IO_ERROR;
	}
	if (_fseeki64(fp_write, chunk_offset, SEEK_SET) != 0){
		perror("Failed to seek temporary file");
		fclose(fp_read);
		fclose(fp_write);
		return RET_FILE_IO_ERROR;
	}

	file_offset = 0;
	total_packet_size = 0;
	while (total_packet_size < chunk_size){
		// Skip found input file slices in damaged file
		slice_index = 0;
		while (slice_index < slice_count){
			if (slice_list[slice_index].find_name != NULL){
				slice_offset = slice_list[slice_index].find_offset;
				slice_size = slice_list[slice_index].size;
				if ( (slice_offset + slice_size > file_offset) && (slice_offset < file_offset + 48) ){
					//printf("file_offset = %" PRId64 ", slice_index = %" PRId64 "\n", file_offset, slice_index);
					file_offset = slice_offset + slice_size;
					// Check again from the first slice
					slice_index = 0;
					continue;
				}
			}
			slice_index++;
		}
		if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
			perror("Failed to seek Outside file");
			fclose(fp_read);
			fclose(fp_write);
			return RET_FILE_IO_ERROR;
		}

		// Read some packets at once
		buf_size = fread(buf, 1, alloc_size, fp_read);
		if (par3_ctx->noise_level >= 3){
			printf("file_offset = %" PRId64 ", buf_size = %" PRId64 "\n", file_offset, buf_size);
		}
		offset = 0;
		while (offset + 48 < buf_size){
			if (memcmp(buf + offset, "PAR3\0PKT", 8) == 0){	// check Magic sequence
				// read packet size
				memcpy(&packet_size, buf + (offset + 24), 8);
				if (packet_size <= 48){	// If packet is too small, just ignore it.
					offset += 8;
					continue;
				}
				// If packet exceeds buffer, read more bytes.
				if (offset + packet_size > buf_size){
					// slide data to top
					memmove(buf, buf + offset, buf_size - offset);
					file_offset += offset;
					// read following data
					buf_size = buf_size - offset + fread(buf + buf_size - offset, 1, offset, fp_read);
					if (par3_ctx->noise_level >= 3){
						printf("file_offset = %" PRId64 ", buf_size = %" PRId64 ", offset = %" PRId64 ", packet_size = %" PRId64 "\n", file_offset, buf_size, offset, packet_size);
					}
					offset = 0;
					if (packet_size > buf_size){
						offset += 8;
						continue;
					}
				}

				// check fingerprint hash of the packet
				blake3(buf + (offset + 24), packet_size - 24, buf_hash);
				if (memcmp(buf + (offset + 8), buf_hash, 16) != 0){
					// If checksum is different, ignore the packet.
					offset += 8;
					continue;
				}
				if (par3_ctx->noise_level >= 3){
					printf("Complete packet: offset = %" PRId64 " + %" PRId64 ", size = %" PRId64 "\n", file_offset, offset, packet_size);
				}

				// write packet on temporary file
				if (fwrite(buf + offset, 1, packet_size, fp_write) != packet_size){
					perror("Failed to write packet on temporary file");
					fclose(fp_read);
					fclose(fp_write);
					return RET_FILE_IO_ERROR;
				}
				total_packet_size += packet_size;

				offset += packet_size;
			} else {
				offset++;
			}
		}
		file_offset += offset;

		// Exit at end of file
		if (feof(fp_read) != 0)
			break;
	}

	if (fclose(fp_read) != 0){
		perror("Failed to close Outside file");
		fclose(fp_write);
		return RET_FILE_IO_ERROR;
	}
	if (fclose(fp_write) != 0){
		perror("Failed to close temporary file");
		return RET_FILE_IO_ERROR;
	}

	free(buf);
	par3_ctx->work_buf = NULL;

	if (par3_ctx->noise_level >= 2){
		printf("Total size of copied complete packets = %" PRId64 "\n", total_packet_size);
	}

	return 0;
}

