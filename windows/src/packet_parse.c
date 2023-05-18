
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "common.h"


// Count number of chunk descriptions.
static int count_chunk_description(PAR3_CTX *par3_ctx, uint8_t *chunk, size_t description_size)
{
	size_t offset;
	uint64_t block_size, chunk_size, tail_size;

	block_size = par3_ctx->block_size;

	offset = 0;
	while (offset < description_size){
		par3_ctx->chunk_count++;

		memcpy(&chunk_size, chunk + offset, 8);
		offset += 8;	// length of chunk
		if (chunk_size == 0){	// zeros if not protected
			offset += 8;
		} else {
			if (block_size == 0){
				printf("Block size must be larger than 0 for chunk.\n");
				return RET_LOGIC_ERROR;
			}
			if (chunk_size >= block_size){
				offset += 8;	// index of first input block holding chunk
			}
			tail_size = chunk_size % block_size;
			if (tail_size < 40){
				offset += tail_size;	// tail is 1 ~ 39.
			} else {
				offset += 40;
			}
		}
	}
	if (offset != description_size){
		printf("Size of chunk description is wrong, %zu\n", description_size);
		return RET_LOGIC_ERROR;
	}

	return 0;
}

// Read packets and count number of files and directories.
// Check error or missing data, too.
static int count_directory_tree(PAR3_CTX *par3_ctx, uint8_t *checksum, size_t checksum_size, size_t dir_len)
{
	uint8_t *file_packet, *dir_packet;
	int ret, flag_find;
	uint32_t num;
	size_t checksum_offset, len, offset;
	size_t file_packet_size, dir_packet_size, packet_size, packet_offset;

	if ( (checksum_size == 0) || (checksum_size & 15) ){
		printf("Size of checksums for children is wrong, %zu\n", checksum_size);
		return RET_LOGIC_ERROR;
	}

	file_packet = par3_ctx->file_packet;
	file_packet_size = par3_ctx->file_packet_size;
	dir_packet = par3_ctx->dir_packet;
	dir_packet_size = par3_ctx->dir_packet_size;

	checksum_offset = 0;
	while (checksum_offset < checksum_size){
		flag_find = 0;
		if (file_packet_size > 0){
			packet_offset = 0;
			while (packet_offset < file_packet_size){
				memcpy(&packet_size, file_packet + packet_offset + 24, 8);
				if (packet_size >= 60){
					if (memcmp(checksum + checksum_offset, file_packet + packet_offset + 8, 16) == 0){
						flag_find = 1;
						par3_ctx->input_file_count++;

						// file name
						offset = 48;
						len = 0;
						memcpy(&len, file_packet + packet_offset + offset, 2);	// length of string in bytes
						if (len == 0){
							printf("file name is too short.\n");
							return RET_LOGIC_ERROR;
						} else if (dir_len + len >= _MAX_PATH){
							printf("Input file's path is too long.\n");
							return RET_LOGIC_ERROR;
						}
						par3_ctx->input_file_name_max += dir_len + len + 1;

						// options
						offset += 2 + len + 8 + 16;
						num = 0;
						memcpy(&num, file_packet + packet_offset + offset, 1);	// number of options
						//printf("number of options = %u\n", num);

						// chunk descriptions
						offset += 1 + 16 * num;
						if (offset < packet_size){
							ret = count_chunk_description(par3_ctx, file_packet + packet_offset + offset, packet_size - offset);
							if (ret != 0)
								return ret;
						} else if (offset > packet_size){	// Either length of name or number of options is wrong.
							printf("File Packet data is wrong.\n");
							return RET_LOGIC_ERROR;
						}
						break;
					}
				}
				packet_offset += packet_size;
			}
		}
		if ( (flag_find == 0) && (dir_packet_size > 0) ){
			packet_offset = 0;
			while (packet_offset < dir_packet_size){
				memcpy(&packet_size, dir_packet + packet_offset + 24, 8);
				if (packet_size >= 55){
					if (memcmp(checksum + checksum_offset, dir_packet + packet_offset + 8, 16) == 0){
						flag_find = 1;
						par3_ctx->input_dir_count++;

						// directory name
						offset = 48;
						len = 0;
						memcpy(&len, dir_packet + packet_offset + offset, 2);	// length of string in bytes
						if (len == 0){
							printf("directory name is too short.\n");
							return RET_LOGIC_ERROR;
						} else if (dir_len + len >= _MAX_PATH){
							printf("Input directory's path is too long.\n");
							return RET_LOGIC_ERROR;
						}
						// PAR3 file's absolute path is enabled, only when a user set option.
						if ( (dir_len == 0) && ((par3_ctx->attribute & 1) != 0) && (par3_ctx->absolute_path != 0) ){
							// It doesn't check drive letter at this time.
							dir_len++;	// add "/" at the top
						}
						par3_ctx->input_dir_name_max += dir_len + len + 1;

						// options
						offset += 2 + len;
						memcpy(&num, dir_packet + packet_offset + offset, 4);	// number of options
						offset += 4 + 16 * num;
						if (offset < packet_size){
							// goto children
							ret = count_directory_tree(par3_ctx, dir_packet + packet_offset + offset, packet_size - offset, dir_len + len + 1);
							if (ret != 0)
								return ret;
						} else if (offset > packet_size){	// Either length of name or number of options is wrong.
							printf("Directory Packet data is wrong.\n");
							return RET_LOGIC_ERROR;
						}
						break;
					}
				}
				packet_offset += packet_size;
			}
		}
		if (flag_find == 0){
			printf("File Packet or Directory Packet is missing.\n");
			return RET_INSUFFICIENT_DATA;
		}

		checksum_offset += 16;
	}

	return 0;
}

static int parse_chunk_description(PAR3_CTX *par3_ctx, uint8_t *chunk, size_t description_size)
{
	uint8_t buf_tail[40];
	uint32_t chunk_num;
	size_t offset;
	uint64_t block_size, block_count;
	uint64_t chunk_size, tail_size, file_size;
	PAR3_CHUNK_CTX *chunk_p;
	PAR3_FILE_CTX *file_p;

	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	chunk_p = par3_ctx->chunk_list + par3_ctx->chunk_count;
	file_p = par3_ctx->input_file_list + par3_ctx->input_file_count;

	chunk_num = 0;
	file_size = 0;
	offset = 0;
	while (offset < description_size){
		memcpy(&chunk_size, chunk + offset, 8);
		offset += 8;	// length of chunk
		chunk_p->size = chunk_size;
		if (chunk_size == 0){	// zeros if not protected
			// Unprotected Chunk Description
			file_p->state |= 0x80000000;
			memcpy(&(chunk_p->block), chunk + offset, 8);	// length of chunk
			offset += 8;
			file_size += chunk_p->block;

		} else {
			// Protected Chunk Description
			if (block_size == 0){
				printf("Block size must be larger than 0 for chunk.\n");
				return RET_LOGIC_ERROR;
			}
			file_size += chunk_size;
			if (chunk_size >= block_size){
				memcpy(&(chunk_p->block), chunk + offset, 8);
				if (chunk_p->block >= block_count){
					printf("First block of chunk exceeds block count. %I64u\n", chunk_p->block);
					return RET_LOGIC_ERROR;
				}
				offset += 8;	// index of first input block holding chunk
			} else {
				chunk_p->block = 0;
			}
			tail_size = chunk_size % block_size;
			if (tail_size < 40){
				memcpy(buf_tail, chunk + offset, tail_size);
				memset(buf_tail + tail_size, 0, 40 - tail_size);
				offset += tail_size;	// tail is 1 ~ 39.
			} else {
				memcpy(buf_tail, chunk + offset, 40);
				offset += 40;
			}
			memcpy(&(chunk_p->tail_crc), buf_tail, 8);
			memcpy(chunk_p->tail_hash, buf_tail + 8, 16);
			memcpy(&(chunk_p->tail_block), buf_tail + 24, 8);
			memcpy(&(chunk_p->tail_offset), buf_tail + 32, 8);
			if (tail_size >= 40){
				if (chunk_p->tail_block >= block_count){
					printf("Tail block of chunk exceeds block count. %I64u\n", chunk_p->tail_block);
					return RET_LOGIC_ERROR;
				}
			}
		}

		chunk_num++;
		par3_ctx->chunk_count++;
		chunk_p++;
	}
	if (offset != description_size){
		printf("Size of chunk description is wrong, %zu\n", description_size);
		return RET_LOGIC_ERROR;
	}
	file_p->size = file_size;
	file_p->chunk_num = chunk_num;

	return 0;
}

// construct directory tree from root to child
static int construct_directory_tree(PAR3_CTX *par3_ctx, uint8_t *checksum, size_t checksum_size, char *sub_dir)
{
	uint8_t *file_packet, *dir_packet;
	int ret, flag_find;
	uint32_t num;
	size_t checksum_offset, dir_len, len, offset;
	size_t file_packet_size, dir_packet_size, packet_size, packet_offset;
	PAR3_FILE_CTX *file_p;
	PAR3_DIR_CTX *dir_p;

	if ( (checksum_size == 0) || (checksum_size & 15) ){
		printf("Size of checksums for children is wrong, %zu\n", checksum_size);
		return RET_LOGIC_ERROR;
	}

	file_packet = par3_ctx->file_packet;
	file_packet_size = par3_ctx->file_packet_size;
	dir_packet = par3_ctx->dir_packet;
	dir_packet_size = par3_ctx->dir_packet_size;

	dir_len = strlen(sub_dir);
	checksum_offset = 0;
	while (checksum_offset < checksum_size){
		flag_find = 0;
		if (file_packet_size > 0){
			packet_offset = 0;
			while (packet_offset < file_packet_size){
				memcpy(&packet_size, file_packet + packet_offset + 24, 8);
				if (packet_size >= 60){
					if (memcmp(checksum + checksum_offset, file_packet + packet_offset + 8, 16) == 0){
						flag_find = 1;
						file_p = par3_ctx->input_file_list + par3_ctx->input_file_count;
						file_p->offset = packet_offset;	// offset of packet
						memcpy(file_p->chk, file_packet + packet_offset + 8, 16);	// checksum of packet

						// file name
						offset = 48;
						len = 0;
						memcpy(&len, file_packet + packet_offset + offset, 2);
						if (len == 0){
							printf("file name is too short.\n");
							return RET_LOGIC_ERROR;
						} else if (dir_len + len >= _MAX_PATH){
							printf("Input file's path is too long.\n");
							return RET_LOGIC_ERROR;
						}
						offset += 2;
						memcpy(sub_dir + dir_len, file_packet + packet_offset + offset, len);
						sub_dir[dir_len + len] = 0;
						if (par3_ctx->noise_level >= 3){
							printf("input file = \"%s\"\n", sub_dir);
						}
						ret = sanitize_file_name(sub_dir + dir_len);
						if (par3_ctx->noise_level >= 0){
							if (ret & 1){
								printf("Warning, file name was sanitized to \"%s\".\n", sub_dir + dir_len);
							} else if (ret & 2){
								printf("Warning, file name \"%s\" is bad.\n", sub_dir + dir_len);
							}
						}

						// check name in list
						if (namez_search(par3_ctx->input_file_name, par3_ctx->input_file_name_len, sub_dir) != NULL){
							printf("There is same file name already. %s\n", sub_dir);
							return RET_LOGIC_ERROR;
						}

						// add found filename
						if (namez_add(&(par3_ctx->input_file_name), &(par3_ctx->input_file_name_len), &(par3_ctx->input_file_name_max), sub_dir) != 0){
							printf("Failed to add file name. %s\n", sub_dir);
							return RET_MEMORY_ERROR;
						}
						file_p->name = par3_ctx->input_file_name + par3_ctx->input_file_name_len - (dir_len + len + 1);

						// hash of the first 16kB of the file
						offset += len;
						memcpy(&(file_p->crc), file_packet + packet_offset + offset, 8);

						// hash of the protected data in the file
						offset += 8;
						memcpy(file_p->hash, file_packet + packet_offset + offset, 16);

						// options
						offset += 16;
						num = 0;
						memcpy(&num, file_packet + packet_offset + offset, 1);	// number of options

						// At this time, this doesn't support options yet.
						//printf("number of options = %u\n", num);

						// chunk descriptions
						file_p->size = 0;
						file_p->chunk = par3_ctx->chunk_count;
						file_p->chunk_num = 0;
						file_p->state = 0;
						offset += 1 + 16 * num;
						if (offset < packet_size){	// When there are chunk descriptions.
							ret = parse_chunk_description(par3_ctx, file_packet + packet_offset + offset, packet_size - offset);
							if (ret != 0)
								return ret;
						} else if (offset > packet_size){	// Either length of name or number of options is wrong.
							printf("File Packet data is wrong.\n");
							return RET_LOGIC_ERROR;
						}
						par3_ctx->input_file_count++;

						break;
					}
				}
				packet_offset += packet_size;
			}
		}
		if ( (flag_find == 0) && (dir_packet_size > 0) ){
			packet_offset = 0;
			while (packet_offset < dir_packet_size){
				memcpy(&packet_size, dir_packet + packet_offset + 24, 8);
				if (packet_size >= 55){
					if (memcmp(checksum + checksum_offset, dir_packet + packet_offset + 8, 16) == 0){
						flag_find = 1;
						dir_p = par3_ctx->input_dir_list + par3_ctx->input_dir_count;
						dir_p->offset = packet_offset;	// offset of packet
						memcpy(dir_p->chk, dir_packet + packet_offset + 8, 16);	// checksum of packet

						// directory name
						offset = 48;
						len = 0;
						memcpy(&len, dir_packet + packet_offset + offset, 2);	// length of string in bytes
						if (len == 0){
							printf("directory name is too short.\n");
							return RET_LOGIC_ERROR;
						} else if (dir_len + len >= _MAX_PATH){
							printf("Input directory's path is too long.\n");
							return RET_LOGIC_ERROR;
						}
						offset += 2;
						memcpy(sub_dir + dir_len, dir_packet + packet_offset + offset, len);
						sub_dir[dir_len + len] = 0;
						if (par3_ctx->noise_level >= 3){
							printf("input dir  = \"%s\"\n", sub_dir);
						}
						// PAR3 file's absolute path is enabled, only when a user set option.
						if ( (dir_len == 0) && ((par3_ctx->attribute & 1) != 0) && (par3_ctx->absolute_path != 0) ){
							if ( (len == 2) && (sub_dir[1] == ':') ){
								sub_dir[1] = '_';	// replace drive letter mark temporary
								ret = sanitize_file_name(sub_dir);
								sub_dir[1] = ':';	// return to original mark
							} else {
								ret = sanitize_file_name(sub_dir);
								memmove(sub_dir + 1, sub_dir, len + 1);	// slide name by including the last null-string
								sub_dir[0] = '/';
								dir_len++;	// add "/" at the top
							}
						} else {
							ret = sanitize_file_name(sub_dir + dir_len);
						}
						if (par3_ctx->noise_level >= 0){
							if (ret & 1){
								printf("Warning, directory name was sanitized to \"%s\".\n", sub_dir + dir_len);
							} else if (ret & 2){
								printf("Warning, directory name \"%s\" is bad.\n", sub_dir + dir_len);
							}
						}

						// check name in list
						if (namez_search(par3_ctx->input_dir_name, par3_ctx->input_dir_name_len, sub_dir) != NULL){
							printf("There is same directory name already. %s\n", sub_dir);
							return RET_LOGIC_ERROR;
						}

						// add found name
						if (namez_add(&(par3_ctx->input_dir_name), &(par3_ctx->input_dir_name_len), &(par3_ctx->input_dir_name_max), sub_dir) != 0){
							printf("Failed to add directory name. %s\n", sub_dir);
							return RET_MEMORY_ERROR;
						}
						dir_p->name = par3_ctx->input_dir_name + par3_ctx->input_dir_name_len - (dir_len + len + 1);
						par3_ctx->input_dir_count++;

						// options
						offset += len;
						memcpy(&num, dir_packet + packet_offset + offset, 4);	// number of options
						offset += 4 + 16 * num;
						if (offset < packet_size){
							// goto children
							// Though Windows OS supports both "/" and "\" as directory mark, I use "/" here for compatibility.
							sub_dir[dir_len + len] = '/';	// directory mark
							sub_dir[dir_len + len + 1] = 0;
							ret = construct_directory_tree(par3_ctx, dir_packet + packet_offset + offset, packet_size - offset, sub_dir);
							if (ret != 0)
								return ret;
						} else if (offset > packet_size){	// Either length of name or number of options is wrong.
							printf("Directory Packet data is wrong.\n");
							return RET_LOGIC_ERROR;
						}

						break;
					}
				}
				packet_offset += packet_size;
			}
		}
		if (flag_find == 0){
			printf("File Packet or Directory Packet is missing.\n");
			return RET_INSUFFICIENT_DATA;
		}

		checksum_offset += 16;
	}

	return 0;
}

// parse information in packets
int parse_vital_packet(PAR3_CTX *par3_ctx)
{
	char file_path[_MAX_PATH];
	uint8_t *tmp_p;
	int ret;
	uint32_t num;
	size_t len;
	uint64_t packet_size;

	if (par3_ctx->noise_level >= 0){
		// Read and show Creator text
		if (par3_ctx->creator_packet_size > 0){
			memcpy(&packet_size, par3_ctx->creator_packet + 24, 8);
			if (packet_size > 48){
				len = packet_size - 48;
				//printf("creator len = %zu\n", len);
				tmp_p = malloc(len + 1);	// allocate buffer for the last null-string
				if (tmp_p != NULL){
					memcpy(tmp_p, par3_ctx->creator_packet + 48, len);
					tmp_p[len] = 0;
					printf("\nCreator text:\n");
					if (tmp_p[len - 1] == '\n'){
						printf("%s", tmp_p);
					} else {
						printf("%s\n", tmp_p);
					}
					free(tmp_p);
				}
			}
		}

		// Read and show Comment text
		if (par3_ctx->comment_packet_size > 0){
			memcpy(&packet_size, par3_ctx->comment_packet + 24, 8);
			if (packet_size > 48){
				len = packet_size - 48;
				tmp_p = malloc(len + 1);	// allocate buffer for the last null-string
				if (tmp_p != NULL){
					memcpy(tmp_p, par3_ctx->comment_packet + 48, len);
					tmp_p[len] = 0;
					if (strchr(tmp_p, '\n') == NULL){
						printf("\nComment text: %s\n", tmp_p);
					} else {
						printf("\nComment text:\n");
						printf("%s\n", tmp_p);
					}
					free(tmp_p);
				}
			}
		}
	}

	// Read Start Packet
	if (par3_ctx->start_packet_size > 0){
		memcpy(&packet_size, par3_ctx->start_packet + 24, 8);
		len = 48;	// size of packet header
		if (packet_size >= 89){	// To support old Start Packet for compatibility
			// This will be removed in future, when PAR3 spec is updated.
			len += 8;
			//printf("Start Packet is old, %I64u\n", packet_size);
		}
		if (mem_or8(par3_ctx->start_packet + len) != 0){	// check parent's InputSetID
			if (mem_or16(par3_ctx->start_packet + len + 8) == 0){	// check parent's Root packet
				printf("Checksum of the parent's Root Packet is wrong.\n");
				return RET_LOGIC_ERROR;
			}
		}
		memcpy(&(par3_ctx->block_size), par3_ctx->start_packet + len + 24, 8);
		memcpy(&(par3_ctx->gf_size), par3_ctx->start_packet + len + 32, 1);
		if (par3_ctx->gf_size > 2){	// At this time, this supports 8-bit or 16-bit Galois Field only.
			printf("Size of Galois Field is too large, %u\n", par3_ctx->gf_size);
			return RET_LOGIC_ERROR;
		}
		if ( (par3_ctx->gf_size > 0) && (par3_ctx->gf_size < 4) ){
			memcpy(&(par3_ctx->galois_poly), par3_ctx->start_packet + len + 33, par3_ctx->gf_size);
			par3_ctx->galois_poly |= 1 << (par3_ctx->gf_size * 8);
		}
		if (packet_size != len + 33 + par3_ctx->gf_size){	// check packet size is valid
			printf("Start Packet size is wrong, %I64u\n", packet_size);
			return RET_LOGIC_ERROR;
		}
	}
	if (par3_ctx->noise_level >= 0){
		printf("\n");
		printf("Block size = %I64u\n", par3_ctx->block_size);
		if (par3_ctx->noise_level >= 1){
			printf("Galois field size = %u\n", par3_ctx->gf_size);
			printf("Galois field generator = 0x%X\n", par3_ctx->galois_poly);
		}
	}

	// Read Root Packet
	if ( (par3_ctx->root_packet_size == 0) || (par3_ctx->root_packet_count == 0) ){
		printf("There is no Root Packet.\n");
		return RET_INSUFFICIENT_DATA;
	}
	if (par3_ctx->root_packet_count > 1){
		printf("There are multiple different Root Packets.\n");
		return RET_LOGIC_ERROR;
	}
	memcpy(&packet_size, par3_ctx->root_packet + 24, 8);
	if (packet_size <= 61){
		printf("Root Packet is too small, %I64u\n", packet_size);
		return RET_INSUFFICIENT_DATA;
	}
	tmp_p = par3_ctx->root_packet + 48;	// packet body
	memcpy(&(par3_ctx->block_count), tmp_p, 8);
	memcpy(&(par3_ctx->attribute), tmp_p + 8, 1);
	memcpy(&num, tmp_p + 9, 4);	// number of options
	if (packet_size < 48 + 8 + 1 + 4 + (16 * num)){
		printf("Root Packet is too small, %I64u\n", packet_size);
		return RET_INSUFFICIENT_DATA;
	}
	tmp_p += 8 + 1 + 4 + (16 * num);	// skip options at this time
	len = packet_size - 48 - (8 + 1 + 4) - (16 * num);
	if ( (len == 0) || (len & 15) ){
		printf("Size of checksums for children is wrong, %zu\n", len);
		return RET_LOGIC_ERROR;
	}
	if (par3_ctx->noise_level >= 0){
		printf("Block count = %I64u\n", par3_ctx->block_count);
		printf("Root attribute = %u\n", par3_ctx->attribute);
	}

	// count number of files and directories
	// total length of file and directory names
	par3_ctx->chunk_count = 0;
	par3_ctx->input_file_count = 0;
	par3_ctx->input_dir_count = 0;
	par3_ctx->input_file_name_max = 0;
	par3_ctx->input_dir_name_max = 0;
	ret = count_directory_tree(par3_ctx, tmp_p, len, 0);
	if (ret != 0)
		return ret;
	if ( (par3_ctx->block_count > 0) && (par3_ctx->chunk_count == 0) ){
		printf("There is no chunk description.\n");
		return RET_LOGIC_ERROR;
	}
	if (par3_ctx->noise_level >= 0){
		printf("Number of input file = %u, directory = %u\n", par3_ctx->input_file_count, par3_ctx->input_dir_count);
		printf("Number of chunk description = %u\n", par3_ctx->chunk_count);
	}
	//printf("input_file_name_max = %zu, input_dir_name_max = %zu\n", par3_ctx->input_file_name_max, par3_ctx->input_dir_name_max);

	// allocate memory for file and directory name
	if (par3_ctx->input_file_name != NULL){
		free(par3_ctx->input_file_name);
		par3_ctx->input_file_name = NULL;
	}
	if (par3_ctx->input_file_name_max > 0){
		par3_ctx->input_file_name = malloc(par3_ctx->input_file_name_max);
		if (par3_ctx->input_file_name == NULL){
			perror("Failed to allocate memory for file name");
			return RET_MEMORY_ERROR;
		}
	}
	par3_ctx->input_file_name_len = 0;
	if (par3_ctx->input_dir_name != NULL){
		free(par3_ctx->input_dir_name);
		par3_ctx->input_dir_name = NULL;
	}
	if (par3_ctx->input_dir_name_max > 0){
		par3_ctx->input_dir_name = malloc(par3_ctx->input_dir_name_max);
		if (par3_ctx->input_dir_name == NULL){
			perror("Failed to allocate memory for directory name");
			return RET_MEMORY_ERROR;
		}
	}
	par3_ctx->input_dir_name_len = 0;

	// allocate memory for chunk, file, and directory info
	if (par3_ctx->chunk_list != NULL){
		free(par3_ctx->chunk_list);
		par3_ctx->chunk_list = NULL;
	}
	if (par3_ctx->chunk_count > 0){
		par3_ctx->chunk_list = malloc(sizeof(PAR3_CHUNK_CTX) * par3_ctx->chunk_count);
		if (par3_ctx->chunk_list == NULL){
			perror("Failed to allocate memory for chunk description");
			return RET_MEMORY_ERROR;
		}
	}
	par3_ctx->chunk_count = 0;
	if (par3_ctx->input_file_list != NULL){
		free(par3_ctx->input_file_list);
		par3_ctx->input_file_list = NULL;
	}
	if (par3_ctx->input_file_count > 0){
		par3_ctx->input_file_list = malloc(sizeof(PAR3_FILE_CTX) * par3_ctx->input_file_count);
		if (par3_ctx->input_file_list == NULL){
			perror("Failed to allocate memory for input file");
			return RET_MEMORY_ERROR;
		}
	}
	par3_ctx->input_file_count = 0;
	if (par3_ctx->input_dir_list != NULL){
		free(par3_ctx->input_dir_list);
		par3_ctx->input_dir_list = NULL;
	}
	if (par3_ctx->input_dir_count > 0){
		par3_ctx->input_dir_list = malloc(sizeof(PAR3_DIR_CTX) * par3_ctx->input_dir_count);
		if (par3_ctx->input_dir_list == NULL){
			perror("Failed to allocate memory for input directory");
			return RET_MEMORY_ERROR;
		}
	}
	par3_ctx->input_dir_count = 0;

	// directory tree
	file_path[0] = 0;
	ret = construct_directory_tree(par3_ctx, tmp_p, len, file_path);
	if (ret != 0)
		return ret;
	//printf("input_file_name_len = %zu, input_file_name_max = %zu\n", par3_ctx->input_file_name_len, par3_ctx->input_file_name_max);
	//printf("input_dir_name_len = %zu, input_dir_name_max = %zu\n", par3_ctx->input_dir_name_len, par3_ctx->input_dir_name_max);


/*
	// read OK ?
	if (par3_ctx->noise_level >= 0){
		if (par3_ctx->input_file_count > 0){
			PAR3_FILE_CTX *file_p;

			printf("\nNumber of input file = %u (chunk = %u)\n", par3_ctx->input_file_count, par3_ctx->chunk_count);
			file_p = par3_ctx->input_file_list;
			num = par3_ctx->input_file_count;
			while (num > 0){
				printf("input file = \"%s\", size = %I64u\n", file_p->name, file_p->size);
				//printf("index of file = %u, index of the first chunk = %u\n", par3_ctx->input_file_count, file_p->chunk);

				file_p++;
				num--;
			}
		}
		if (par3_ctx->input_dir_count > 0){
			PAR3_DIR_CTX *dir_p;

		printf("\nNumber of input directory = %u\n", par3_ctx->input_dir_count);
			dir_p = par3_ctx->input_dir_list;
			num = par3_ctx->input_dir_count;
			while (num > 0){
				printf("input dir  = \"%s\"\n", dir_p->name);

				dir_p++;
				num--;
			}
		}
	}
	printf("Done\n");
*/

	return 0;
}

// parse information in External Data Packets
int parse_external_data_packet(PAR3_CTX *par3_ctx)
{
	uint8_t *tmp_p, *hash;
	uint32_t num;
	uint64_t block_count, packet_size, index, count;
	PAR3_BLOCK_CTX *block_p, *block_list;

	num = par3_ctx->ext_data_packet_count;
	block_count = par3_ctx->block_count;
	block_list = par3_ctx->block_list;
	tmp_p = par3_ctx->ext_data_packet;
	while (num > 0){
		memcpy(&packet_size, tmp_p + 24, 8);
		if (packet_size < 48 + 8 + 24){
			printf("External Data Packet is too small.\n");
			return RET_LOGIC_ERROR;
		}
		memcpy(&index, tmp_p + 48, 8);	// Index of the first input block
		hash = tmp_p + 56;
		count = packet_size - 56;
		if (count % 24 != 0){
			printf("External Data Packet for %I64u is bad.\n", index);
			return RET_LOGIC_ERROR;
		}
		count /= 24;
		if (index + count > block_count){
			printf("External Data Packet for %I64u is too large (%I64u).\n", index, count);
			return RET_LOGIC_ERROR;
		}

		// set hash values for blocks
		block_p = block_list + index;
		while (count > 0){
			memcpy(&(block_p->crc), hash, 8);
			hash += 8;
			memcpy(block_p->hash, hash, 16);
			hash += 16;
			block_p->state |= 64;	// mark of setting checksum for this block

			block_p++;
			count--;
		}

		tmp_p += packet_size;
		num--;
	}

	if (par3_ctx->noise_level >= 1){
		// Checksum for full size blocks is required for verification.
		// But, checking complete file by file's hash may be possible.
		for (index = 0; index < block_count; index++){
			//printf("block[%2I64u] crc = 0x%016I64x\n", index, block_list[index].crc);
			if ((block_list[index].state & (1 | 64)) == 1){
				printf("Warning, checksum of input block[%I64u] doesn't exist.\n", index);
			}
		}
	}

	return 0;
}

