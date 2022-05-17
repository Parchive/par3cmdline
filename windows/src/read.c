
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// MSVC headers
#include <io.h>

#include "blake3/blake3.h"
#include "libpar3.h"
#include "common.h"
#include "hash.h"
#include "packet.h"


int read_vital_packet(PAR3_CTX *par3_ctx)
{
	char *namez, packet_type[9];
	uint8_t *buf, buf_hash[16];
	int ret;
	size_t namez_len, namez_off;
	size_t buf_size, read_size, max, offset;
	uint64_t file_size, file_offset, packet_size;
	uint64_t packet_count, new_packet_count;
	FILE *fp;

	//for debug
	//par3_ctx->memory_limit = 1024;

	packet_type[8] = 0;	// Set null string.

	// Allocate buffer to keep PAR file.
	buf_size = par3_ctx->max_file_size;
	if ( (par3_ctx->memory_limit != 0) && (buf_size > par3_ctx->memory_limit) ){
		buf_size = par3_ctx->memory_limit;	// multiple of MB
		// When buffer size is 1 MB, readable minimum packet size becomes 1 MB, too.
		// So, a user should not set small limit.
	}
	if (par3_ctx->noise_level >= 2){
		printf("buffer size for PAR files = %I64u\n", buf_size);
	}
	buf = malloc(buf_size);
	if (buf == NULL){
		perror("Failed to allocate memory for PAR files");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->work_buf = buf;

	namez = par3_ctx->par_file_name;
	namez_len = par3_ctx->par_file_name_len;
	namez_off = 0;
	while (namez_off < namez_len){
		if (par3_ctx->noise_level >= -1){
			printf("Loading \"%s\".\n", namez + namez_off);
		}

		fp = fopen(namez + namez_off, "rb");
		if (fp == NULL){
			printf("Failed to open \"%s\", skip to next file.\n", namez + namez_off);
			namez_off += strlen(namez + namez_off) + 1;
			continue;
		}

		// get file size
		file_size = _filelengthi64(_fileno(fp));

		// Read file data at first.
		read_size = buf_size;
		if (file_size < buf_size)
			read_size = file_size;
		//printf("file data = %I64u, read_size = %zu, remain = %zu\n", file_size, read_size, file_size - read_size);
		if (fread(buf, 1, read_size, fp) != read_size){
			printf("Failed to read \"%s\", skip to next file.\n", namez + namez_off);
			namez_off += strlen(namez + namez_off) + 1;
			fclose(fp);
			continue;
		}
		file_size -= read_size;
		max = read_size;

		file_offset = 0;
		packet_count = 0;
		new_packet_count = 0;
		offset = 0;
		while (offset + 48 < max){
			if (memcmp(buf + offset, "PAR3\0PKT", 8) == 0){	// check Magic sequence
				// read packet size
				memcpy(&packet_size, buf + (offset + 24), 8);
				if (packet_size <= 48){	// If packet is too small, just ignore it.
					offset += 8;
					continue;
				}
				if (offset + packet_size > buf_size + file_size){	// If not enough data, ignore the packet.
					offset += 8;
					continue;
				}
				if (packet_size > buf_size){	// If packet is larger than buffer, show error and continue.
					if (par3_ctx->noise_level >= 1){
						memcpy(packet_type, buf + (offset + 40), 8);
						printf("Warning, packet is too large. size = %I64u, type = %s\n", packet_size, packet_type);
					}
					offset += 8;
					continue;
				}
				// If packet exceeds buffer, read more bytes.
				if (offset + packet_size > buf_size){
					read_size = offset;
					if (read_size > file_size)
						read_size = file_size;

					// slide data to top
					memmove(buf, buf + offset, buf_size - offset);
					//printf("file data = %I64u, offset = %zu, read_size = %zu, ", file_size, offset, read_size);
					if (fread(buf + buf_size - offset, 1, read_size, fp) != read_size){
						printf("Failed to read \"%s\", skip to next file.\n", namez + namez_off);
						namez_off += strlen(namez + namez_off) + 1;
						fclose(fp);
						continue;
					}
					file_size -= read_size;
					max = buf_size - offset + read_size;
					//printf("remain = %I64u, max = %zu\n", file_size, max);
					file_offset += offset;
					offset = 0;
				}

				// check fingerprint hash of the packet
				blake3(buf + (offset + 24), packet_size - 24, buf_hash);
				if (memcmp(buf + (offset + 8), buf_hash, 16) != 0){
					// If checksum is different, ignore the packet.
					offset += 8;
					continue;
				}
				packet_count++;

				// read packet type
				memcpy(packet_type, buf + (offset + 40), 8);
				if (par3_ctx->noise_level >= 2){
					printf("offset =%6I64u, size =%5I64u, type = %s\n", file_offset + offset, packet_size, packet_type);
				}

				// store the found packet
				ret = add_found_packet(par3_ctx, buf + offset);
				if (ret == -2){
					ret = list_found_packet(par3_ctx, buf + offset, namez + namez_off, file_offset + offset);
				}
				if (ret > 0){
					fclose(fp);
					return ret;
				} else if (ret == 0){
					new_packet_count++;
				}

				offset += packet_size;
			} else {
				offset++;
			}

			if ( (file_size > 0) && (offset + 48 >= max) ){	// read more bytes
				read_size = offset;
				if (read_size > file_size)
					read_size = file_size;

				// slide data to top
				memmove(buf, buf + offset, buf_size - offset);
				//printf("file_size = %I64u, offset = %zu, read_size = %zu, ", file_size, offset, read_size);
				if (fread(buf + buf_size - offset, 1, read_size, fp) != read_size){
					printf("Failed to read \"%s\", skip to next file.\n", namez + namez_off);
					namez_off += strlen(namez + namez_off) + 1;
					fclose(fp);
					continue;
				}
				file_size -= read_size;
				max = buf_size - offset + read_size;
				//printf("remain = %I64u, max = %zu\n", file_size, max);
				file_offset += offset;
				offset = 0;
			}
		}

		if (fclose(fp) != 0){
			printf("Failed to close \"%s\", skip to next file.\n", namez + namez_off);
			namez_off += strlen(namez + namez_off) + 1;
			continue;
		}

		if (par3_ctx->noise_level >= 0){
			printf("Loaded %I64u new packets (found %I64u packets)\n", new_packet_count, packet_count);
		}

		namez_off += strlen(namez + namez_off) + 1;
	}
	free(buf);
	par3_ctx->work_buf = NULL;

	if (par3_ctx->noise_level >= 2){
		printf("\nTotal packet:\n");
		if (par3_ctx->creator_packet_count > 0)
			printf("Number of Creator Packets       =%3u (%4I64d bytes)\n", par3_ctx->creator_packet_count, par3_ctx->creator_packet_size);
		if (par3_ctx->comment_packet_count > 0)
			printf("Number of Comment Packets       =%3u (%4I64d bytes)\n", par3_ctx->comment_packet_count, par3_ctx->comment_packet_size);
		if (par3_ctx->start_packet_count > 0)
			printf("Number of Start Packets         =%3u (%4I64d bytes)\n", par3_ctx->start_packet_count, par3_ctx->start_packet_size);
		if (par3_ctx->matrix_packet_count > 0)
			printf("Number of Matrix Packets        =%3u (%4I64d bytes)\n", par3_ctx->matrix_packet_count, par3_ctx->matrix_packet_size);
		if (par3_ctx->file_packet_count > 0)
			printf("Number of File Packets          =%3u (%4I64d bytes)\n", par3_ctx->file_packet_count, par3_ctx->file_packet_size);
		if (par3_ctx->dir_packet_count > 0)
			printf("Number of Directory Packets     =%3u (%4I64d bytes)\n", par3_ctx->dir_packet_count, par3_ctx->dir_packet_size);
		if (par3_ctx->root_packet_count > 0)
			printf("Number of Root Packets          =%3u (%4I64d bytes)\n", par3_ctx->root_packet_count, par3_ctx->root_packet_size);
		if (par3_ctx->ext_data_packet_count > 0)
			printf("Number of External Data Packets =%3u (%4I64d bytes)\n", par3_ctx->ext_data_packet_count, par3_ctx->ext_data_packet_size);
		if (par3_ctx->data_packet_count > 0)
			printf("Number of Data Packets          =%3I64u\n", par3_ctx->data_packet_count);
		if (par3_ctx->rec_data_packet_count > 0)
			printf("Number of Recovery Data Packets =%3I64u\n", par3_ctx->rec_data_packet_count);
	}
	ret = check_packet_set(par3_ctx);
	if (ret != 0)
		return ret;

	return 0;
}

void show_read_result(PAR3_CTX *par3_ctx, int flag_detail)
{
	uint32_t num;

	if (par3_ctx->input_file_count > 0){
		PAR3_FILE_CTX *file_p;

		num = (uint32_t)namez_maxlen(par3_ctx->input_file_name, par3_ctx->input_file_name_len);
		if (num < 8)
			num = 8;
		printf("\n");
		if (flag_detail == 0){
			if (num > 119)
				num = 119;	// max characters per line
			printf(" File (%d)\n", par3_ctx->input_file_count);
			printf(" ");
		} else if (flag_detail == 1){
			if (num > 104)
				num = 104;	// 119 - 15 = 104
			printf(" Size (Bytes)  File (%d)\n", par3_ctx->input_file_count);
			printf(" ------------  ");
		} else {
			if (num > 71)
				num = 71;	// 119 - 48 = 71
			printf(" Size (Bytes)            BLAKE3 Hash            File (%d)\n", par3_ctx->input_file_count);
			printf(" ------------ --------------------------------  ");
		}
		while (num > 0){
			printf("-");
			num--;
		}
		printf("\n");

		file_p = par3_ctx->input_file_list;
		num = par3_ctx->input_file_count;
		while (num > 0){
			if (flag_detail == 0){
				printf("\"%s\"\n", file_p->name);
			} else if (flag_detail == 1){
				printf("%13I64u \"%s\"\n", file_p->size, file_p->name);
			} else {
				printf("%13I64u ", file_p->size);
				printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x ",
					file_p->hash[0], file_p->hash[1], file_p->hash[2], file_p->hash[3],
					file_p->hash[4], file_p->hash[5], file_p->hash[6], file_p->hash[7],
					file_p->hash[8], file_p->hash[9], file_p->hash[10], file_p->hash[11],
					file_p->hash[12], file_p->hash[13], file_p->hash[14], file_p->hash[15]);
				printf("\"%s\"\n", file_p->name);
			}
			//printf("index of file = %u, index of the first chunk = %u\n", par3_ctx->input_file_count, file_p->chunk);

			file_p++;
			num--;
		}
	}
	if (par3_ctx->input_dir_count > 0){
		PAR3_DIR_CTX *dir_p;

		num = (uint32_t)namez_maxlen(par3_ctx->input_dir_name, par3_ctx->input_dir_name_len);
		if (num < 13)
			num = 13;
		if (num > 119)
			num = 119;	// max 120 characters per line
		printf("\n");
		printf(" Directory (%d)\n", par3_ctx->input_dir_count);
		printf(" ");
		while (num > 0){
			printf("-");
			num--;
		}
		printf("\n");

		dir_p = par3_ctx->input_dir_list;
		num = par3_ctx->input_dir_count;
		while (num > 0){
			printf("\"%s\"\n", dir_p->name);

			dir_p++;
			num--;
		}
	}
	printf("\n");
}

void show_data_size(PAR3_CTX *par3_ctx)
{
	uint32_t num;
	uint64_t max_size, total_size;
	PAR3_FILE_CTX *file_p;

	if (par3_ctx->input_file_count == 0)
		return;

	max_size = 0;
	total_size = 0;
	file_p = par3_ctx->input_file_list;
	num = par3_ctx->input_file_count;
	while (num > 0){
		total_size += file_p->size;
		if (max_size < file_p->size)
			max_size = file_p->size;

		file_p++;
		num--;
	}

	par3_ctx->total_file_size = total_size;
	par3_ctx->max_file_size = max_size;

	printf("Total file size = %I64u\n", total_size);
	printf("Max file size = %I64u\n", max_size);
}

