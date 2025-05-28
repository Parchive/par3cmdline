#include "libpar3.h"

#include "common.h"

#include "../blake3/blake3.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "file.h"


// Fill each field in packet header, and calculate hash of packet.
void make_packet_header(uint8_t *buf, uint64_t packet_size, uint8_t *set_id, uint8_t *packet_type, int flag_hash)
{
	memcpy(buf, "PAR3\0PKT", 8);
	if (packet_size > 0)
		memcpy(buf + 24, &packet_size, 8);
	if (set_id != NULL)
		memcpy(buf + 32, set_id, 8);
	if (packet_type != NULL)
		memcpy(buf + 40, packet_type, 8);
	if (flag_hash)
		blake3(buf + 24, packet_size - 24, buf + 8);
}


// Input is packet body of Start Packet.
// Return generated InputSetID at "buf - 16".
static void generate_set_id(PAR3_CTX *par3_ctx, uint8_t *buf, size_t body_size)
{
	uint32_t num, chunk_num;
	size_t len;
	blake3_hasher hasher;
	struct _stat64 stat_buf;

	// prepare a globally unique random number
	blake3_hasher_init(&hasher);

	// all the files' contents
	if (par3_ctx->input_file_count > 0){
		uint32_t index;
		uint64_t total_size, block_size, chunk_size;
		PAR3_FILE_CTX *file_p;
		PAR3_CHUNK_CTX *chunk_list;

		block_size = par3_ctx->block_size;
		chunk_list = par3_ctx->chunk_list;
		file_p = par3_ctx->input_file_list;
		num = par3_ctx->input_file_count;
		while (num > 0){
			// file name
			len = strlen(file_p->name) + 1;	// Include null string as boundary mark.
			blake3_hasher_update(&hasher, file_p->name, len);

			// file size
			blake3_hasher_update(&hasher, &(file_p->size), 8);

			// file hash of protected chunks
			blake3_hasher_update(&hasher, file_p->hash, 16);

			// If it includes options (releated packets), calculate the data also.
			if (par3_ctx->file_system & 0x10003){
				if (_stat64(file_p->name, &stat_buf) == 0){
					if (par3_ctx->file_system & 1)
						blake3_hasher_update(&hasher, &(stat_buf.st_mtime), 8);
					if (par3_ctx->file_system & 2)
						blake3_hasher_update(&hasher, &(stat_buf.st_mode), 8);
					if (par3_ctx->file_system & 0x10000)
						blake3_hasher_update(&hasher, &(stat_buf.st_mtime), 8);
				}
			}

			// Chunk Descriptions
			if (file_p->size > 0){
				total_size = 0;
				index = file_p->chunk;
				chunk_num = file_p->chunk_num;
				while (chunk_num > 0){
					// size of chunk
					chunk_size = chunk_list[index].size;
					total_size += chunk_size;
					blake3_hasher_update(&hasher, &chunk_size, 8);

					if ( (chunk_size == 0) || (chunk_size >= block_size) ){
						// index of first input block holding chunk
						blake3_hasher_update(&hasher, &(chunk_list[index].block), 8);
					}

					if (chunk_size % block_size >= 40){
						// index of block holding tail
						blake3_hasher_update(&hasher, &(chunk_list[index].tail_block), 8);
						blake3_hasher_update(&hasher, &(chunk_list[index].tail_offset), 8);
					}

					// When there are multiple chunks in the file.
					index++;
					chunk_num--;
				}
			}

			file_p++;
			num--;
		}
	}

	// all the directories' contents
	if (par3_ctx->input_dir_count > 0){
		PAR3_DIR_CTX *dir_p;

		dir_p = par3_ctx->input_dir_list;
		num = par3_ctx->input_dir_count;
		while (num > 0){
			// directory name
			len = strlen(dir_p->name) + 1;	// Include null string as boundary mark.
			blake3_hasher_update(&hasher, dir_p->name, len);

			// If it includes options (releated packets), calculate the data also.
			if ( ((par3_ctx->file_system & 4) != 0) && ((par3_ctx->file_system & 3) != 0) ){
				if (_stat64(dir_p->name, &stat_buf) == 0){
					if (par3_ctx->file_system & 1)
						blake3_hasher_update(&hasher, &(stat_buf.st_mtime), 8);
					if (par3_ctx->file_system & 2)
						blake3_hasher_update(&hasher, &(stat_buf.st_mode), 8);
				}
			}

			dir_p++;
			num--;
		}
	}

	// absolute path
	if (par3_ctx->absolute_path != 0){
		uint8_t *tmp_p;

		// convert Windows's directory mark "\" to UNIX's one "/".
		tmp_p = par3_ctx->base_path;
		while (tmp_p[0] != 0){
			if (tmp_p[0] == '\\')
				tmp_p[0] = '/';
			tmp_p++;
		}

		len = strlen(par3_ctx->base_path) + 1;	// Include null string as boundary mark.
		blake3_hasher_update(&hasher, par3_ctx->base_path, len);
	}

	// result in 8-bytes hash for a globally unique random number
	blake3_hasher_finalize(&hasher, buf - 8, 8);

	// calculate hash of packet body for InputSetID
	blake3_hasher_init(&hasher);
	// include bytes of the random number at first
	blake3_hasher_update(&hasher, buf - 8, 8);
	// parent's InputSetID, parent's Root, block size, Galois field parameters
	blake3_hasher_update(&hasher, buf, body_size);
	blake3_hasher_finalize(&hasher, buf - 16, 8);
}


// Start Packet, Creator Packet, Comment Packet
int make_start_packet(PAR3_CTX *par3_ctx, int flag_trial)
{
	uint8_t *tmp_p;
	size_t packet_size;

	// When there is packet already, just exit.
	if (par3_ctx->start_packet_size > 0)
		return 0;

	// Packet size depends on galois field size.
	packet_size = 48 + 8 + 16 + 8 + 1;	// 81 + additional bytes
	if (par3_ctx->start_packet == NULL){
		par3_ctx->start_packet = malloc(packet_size + 4);	// Upto 32-bit Galois Field
		if (par3_ctx->start_packet == NULL){
			perror("Failed to allocate memory for Start Packet");
			return RET_MEMORY_ERROR;
		}
	}

	// Set initial value temporary.
	tmp_p = par3_ctx->start_packet + 48;
	// At this time, "incremental backup" feature isn't made.
	memset(tmp_p, 0, 24);	// When there is no parent, fill zeros.
	tmp_p += 24;
	memcpy(tmp_p, &(par3_ctx->block_size), 8);	// Block size
	tmp_p += 8;
	// Galois Field is varied by using Error Correction Codes.
	if (par3_ctx->ecc_method & 1){	// Reed-Solomon Erasure Codes with Cauchy Matrix
		if ( ( (par3_ctx->block_count > 128) && (par3_ctx->max_recovery_block == 0) )
				|| (par3_ctx->block_count + par3_ctx->first_recovery_block + par3_ctx->recovery_block_count > 256)
				|| (par3_ctx->block_count + par3_ctx->max_recovery_block > 256) ){
			// When there are 129 or more input blocks, use 16-bit Galois Field (0x1100B).
			par3_ctx->galois_poly = 0x1100B;
			par3_ctx->gf_size = 2;
			tmp_p[0] = 2;
			tmp_p[1] = 0x0B;
			tmp_p[2] = 0x10;
		} else if (par3_ctx->block_count > 0){
			// When there are 128 or less input blocks, use 8-bit Galois Field (0x11D).
			par3_ctx->galois_poly = 0x11D;
			par3_ctx->gf_size = 1;
			tmp_p[0] = 1;
			tmp_p[1] = 0x1D;
		}

	} else if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
		// This value is used in Leopard-RS library.
		if ((par3_ctx->first_recovery_block + par3_ctx->recovery_block_count == 1) || (par3_ctx->max_recovery_block == 1)){
			par3_ctx->gf_size = 0;	// XOR sum
		} else if (par3_ctx->block_count > 0){
			uint64_t possible_count, m, n;
			possible_count = par3_ctx->first_recovery_block + par3_ctx->recovery_block_count;
			if (possible_count < par3_ctx->max_recovery_block)
				possible_count = par3_ctx->max_recovery_block;
			// Number of recovery block per cohort
			if (par3_ctx->interleave > 0)
				possible_count = (possible_count + par3_ctx->interleave) / (par3_ctx->interleave + 1);
			m = next_pow2(possible_count);
			//printf("m = next_pow2(%"PRIu64") = %"PRIu64"\n", possible_count, m);
			possible_count = par3_ctx->block_count;
			// Number of input block per cohort
			if (par3_ctx->interleave > 0)
				possible_count = (possible_count + par3_ctx->interleave) / (par3_ctx->interleave + 1);
			n = next_pow2(m + possible_count);
			//printf("n = next_pow2(%"PRIu64" + %"PRIu64") = %"PRIu64"\n", m, possible_count, n);
			if (n <= 256){	// LEO_HAS_FF8
				par3_ctx->galois_poly = 0x11D;
				par3_ctx->gf_size = 1;
				tmp_p[0] = 1;
				tmp_p[1] = 0x1D;
			} else {	// LEO_HAS_FF16
				par3_ctx->galois_poly = 0x1002D;
				par3_ctx->gf_size = 2;
				tmp_p[0] = 2;
				tmp_p[1] = 0x2D;
				tmp_p[2] = 0x00;
			}
		}
	}
	if (par3_ctx->gf_size == 0){	// When there is no input blocks, no need to set Galois Field.
		par3_ctx->galois_poly = 0;
		tmp_p[0] = 0;
	} else {
		if (par3_ctx->noise_level >= 1){
			printf("\nGalois field size = %u\n", par3_ctx->gf_size);
			printf("Galois field generator = 0x%X\n", par3_ctx->galois_poly);
		}
	}
	packet_size += par3_ctx->gf_size;
	par3_ctx->start_packet_size = packet_size;
	par3_ctx->start_packet_count = 1;

	if (flag_trial == 0){	// Trial mode doesn't calculate InputSetID.
		// generate InputSetID
		generate_set_id(par3_ctx, par3_ctx->start_packet + 48, par3_ctx->start_packet_size - 48);
		memcpy(par3_ctx->set_id, par3_ctx->start_packet + 32, 8);
		if (par3_ctx->noise_level >= 1){
			printf("InputSetID = %02X %02X %02X %02X %02X %02X %02X %02X\n",
					par3_ctx->set_id[0], par3_ctx->set_id[1], par3_ctx->set_id[2], par3_ctx->set_id[3],
					par3_ctx->set_id[4], par3_ctx->set_id[5], par3_ctx->set_id[6], par3_ctx->set_id[7]);
		}
	}

	// Because SetID was written already, ignore SetID here.
	make_packet_header(par3_ctx->start_packet, par3_ctx->start_packet_size, NULL, "PAR STA\0", 1);

	// Make header of Creator Packet and Comment Packet, too.
	if (par3_ctx->creator_packet_size > 0)
		make_packet_header(par3_ctx->creator_packet, par3_ctx->creator_packet_size, par3_ctx->set_id, "PAR CRE\0", 1);
	if (par3_ctx->comment_packet_size > 0)
		make_packet_header(par3_ctx->comment_packet, par3_ctx->comment_packet_size, par3_ctx->set_id, "PAR COM\0", 1);

	if (par3_ctx->noise_level >= 1){
		printf("Size of Start Packet = %zu\n", par3_ctx->start_packet_size);
		if (par3_ctx->creator_packet_size > 0)
			printf("Size of Creator Packet = %zu\n", par3_ctx->creator_packet_size);
		if (par3_ctx->comment_packet_size > 0)
			printf("Size of Comment Packet = %zu\n", par3_ctx->comment_packet_size);
	}

	return 0;
}

// Matrix Packet
int make_matrix_packet(PAR3_CTX *par3_ctx)
{
	uint8_t *tmp_p;
	size_t packet_size;

	// When there is no input blocks, just exit.
	if (par3_ctx->block_count == 0)
		return 0;

	// When there is no packet yet, error exit.
	if (par3_ctx->start_packet_size == 0)
		return RET_LOGIC_ERROR;

	// When there is packet already, just exit.
	if (par3_ctx->matrix_packet_size > 0)
		return 0;

	// Max packet size of each type
	// Cauchy Matrix Packet : 48 + 24 = 72
	// Sparse Random Matrix Packet : 48 + 40 = 88
	// Explicit Matrix Packet : not supported yet
	packet_size = 88;	// Set the largest size temporary.
	if (par3_ctx->matrix_packet == NULL){
		par3_ctx->matrix_packet = malloc(packet_size);
		if (par3_ctx->matrix_packet == NULL){
			perror("Failed to allocate memory for Matrix Packet");
			return RET_MEMORY_ERROR;
		}
	}

	if (par3_ctx->ecc_method & 1){	// Cauchy Matrix Packet
		tmp_p = par3_ctx->matrix_packet + 48;
		// If the encoding client wants to compute recovery data for every input block, they use the values 0 and 0.
		if (par3_ctx->max_recovery_block == 0){
			// If the number of rows is unknown, the hint is set to zero.
			memset(tmp_p, 0, 24);	// Thus, three items are zero.
			tmp_p += 24;
		} else {
			memset(tmp_p, 0, 16);	// Two items are zero.
			tmp_p += 16;
			// Set hint for number of recovery blocks
			// This will cause compatibility issue. Be careful !
			memcpy(tmp_p, &(par3_ctx->max_recovery_block), 8);
			tmp_p += 8;
		}
		packet_size = 72;
		make_packet_header(par3_ctx->matrix_packet, packet_size, par3_ctx->set_id, "PAR CAU\0", 1);


/*
	} else if (par3_ctx->ecc_method & 2){	// Sparse Random Matrix Packet
		par3_ctx->ecc_method = 2;
		tmp_p = par3_ctx->matrix_packet + 48;
		// How to know maximum number of recovery blocks ?
		memset(tmp_p, 0, 24);
		tmp_p += 24;
		// How to select number of non-zero elements per input block ?
		// Is it a density rate against number of input blocks ? such like 1%
		
		// How is random number generator seed ?
		// Is it ok to set a fixed value always ?
		// Start Packet has unique random number already.

		packet_size = 88;
		make_packet_header(par3_ctx->matrix_packet, packet_size, par3_ctx->set_id, "PAR SPA\0", 1);
*/

	} else if (par3_ctx->ecc_method & 8){	// FFT Matrix Packet
		tmp_p = par3_ctx->matrix_packet + 48;
		memset(tmp_p, 0, 16);	// At this time, two items are zero.
		tmp_p += 16;
		// If the max count was not set, use the creating number of recovery blocks.
		if (par3_ctx->max_recovery_block < par3_ctx->first_recovery_block + par3_ctx->recovery_block_count)
			par3_ctx->max_recovery_block = par3_ctx->first_recovery_block + par3_ctx->recovery_block_count;
		// Store max count as power. Because the value range is 1 ~ 32768, log2 range is 0 ~ 15.
		if (par3_ctx->interleave == 0){
			tmp_p[0] = roundup_log2(par3_ctx->max_recovery_block);
		} else {	// When interleaving, max count is divided by number of cohorts.
			tmp_p[0] = roundup_log2(par3_ctx->max_recovery_block / (par3_ctx->interleave + 1));
		}
		tmp_p += 1;
		// Store number of interleaving blocks
		// In normal usage, it will be less than 2 bytes.
		// 32,768 blocks * 256 cohorts = max 8,388,608 blocks
		// 32,768 blocks * 65,536 cohorts = max 2,147,483,648 blocks
		// So, it won't use 2 bytes mostly. It won't use 3 or 4 bytes really.
		// Then, par3cmdline doesn't support 5 or more bytes at this time.
		if (par3_ctx->interleave == 0){	// None (0 bytes)
			packet_size = 65;
		} else if (par3_ctx->interleave < 256){	// 1 byte = 1 ~ 255
			memcpy(tmp_p, &(par3_ctx->interleave), 1);
			tmp_p += 1;
			packet_size = 66;
		} else if (par3_ctx->interleave < 65536){	// 2 bytes = 256 ~ 65535
			memcpy(tmp_p, &(par3_ctx->interleave), 2);
			tmp_p += 2;
			packet_size = 67;
		} else if (par3_ctx->interleave < 16777216){	// 3 bytes = 65536 ~ 16777215
			memcpy(tmp_p, &(par3_ctx->interleave), 3);
			tmp_p += 3;
			packet_size = 68;
		} else {	// 4 bytes = 16777216 ~ 4294967295
			memcpy(tmp_p, &(par3_ctx->interleave), 4);
			tmp_p += 4;
			packet_size = 69;
		}
		make_packet_header(par3_ctx->matrix_packet, packet_size, par3_ctx->set_id, "PAR FFT\0", 1);
		//printf("max_recovery_block = %"PRIu64", interleave = %u\n", par3_ctx->max_recovery_block, par3_ctx->interleave);

	} else {
		printf("The specified Error Correction Codes (%u) isn't implemented yet.\n", par3_ctx->ecc_method);
		return RET_LOGIC_ERROR;
	}

	par3_ctx->matrix_packet_size = packet_size;
	par3_ctx->matrix_packet_count = 1;
	if (par3_ctx->noise_level >= 1){
		printf("Size of Matrix Packet = %zu\n", packet_size);
	}

	return 0;
}

static int compare_checksum( const void *arg1, const void *arg2 )
{
	return memcmp( ( unsigned char* ) arg1, ( unsigned char* ) arg2, 16);
}

// File Packet, Directory Packet, Root Packet
int make_file_packet(PAR3_CTX *par3_ctx)
{
	uint8_t *tmp_p, *name_p, *chk_p;
	uint32_t num, max, i, packet_count, absolute_num, option_num;
	size_t alloc_size, packet_size, total_packet_size, len, option_offset;
	size_t file_alloc_size, dir_alloc_size, root_alloc_size, file_system_alloc_size;
	PAR3_FILE_CTX *file_p, *file_list;
	PAR3_DIR_CTX *dir_p, *dir_list;

	// When there is no packet yet, error exit.
	if (par3_ctx->start_packet_size == 0)
		return RET_LOGIC_ERROR;

	// When there is packet already, just exit.
	if (par3_ctx->root_packet_size > 0)
		return 0;

	// Allocate buffer for packets. (This isn't strict size, but a little larger.)
	num = par3_ctx->input_file_count;
	if (num > 0){
		alloc_size = (48 + 2 + 8 + 16 + 1) * num;	// packet header, length of name, CRC-64, hash, options
		if (par3_ctx->file_system & 3)
			alloc_size += 16 * num;	// UNIX Permissions Packet
		if (par3_ctx->file_system & 0x10000)
			alloc_size += 16 * num;	// FAT Permissions Packet
		alloc_size += par3_ctx->input_file_name_len - num;	// subtle null-string of each name
		alloc_size += (16 + 40) * par3_ctx->chunk_count;	// chunk description with tail info
		if (par3_ctx->noise_level >= 2){
			printf("Possible total size of File Packet = %zu\n", alloc_size);
		}
		file_alloc_size = alloc_size;
		if (par3_ctx->file_packet == NULL){
			par3_ctx->file_packet = malloc(alloc_size);
			if (par3_ctx->file_packet == NULL){
				perror("Failed to allocate memory for File Packet");
				return RET_MEMORY_ERROR;
			}
		}
	}

	absolute_num = 0;
	if (par3_ctx->absolute_path != 0){	// Enable absolute path
		par3_ctx->attribute |= 1;
		if (par3_ctx->absolute_path == 'A')	// include drive letter on Windows OS
			absolute_num = 1;
		tmp_p = par3_ctx->base_path;
		while (tmp_p[0] != 0){
			if (tmp_p[0] == '/')
				absolute_num++;
			tmp_p++;
		}
		//printf("Number of directory part in absolute path = %u\n", absolute_num);
	}
	num = par3_ctx->input_dir_count;
	if (num + absolute_num > 0){
		alloc_size = (48 + 2 + 4) * (num + absolute_num);	// packet header, length of name, CRC-64, options
		alloc_size += par3_ctx->input_dir_name_len - num;	// subtle null-string of each name
		if (absolute_num > 0)
			alloc_size += strlen(par3_ctx->base_path);
		num = par3_ctx->input_file_count + par3_ctx->input_dir_count + absolute_num;
		alloc_size += 16 * num;	// checksums of File Packet and Directory Packet
		if (par3_ctx->noise_level >= 2){
			printf("Possible total size of Directory Packet = %zu\n", alloc_size);
		}
		dir_alloc_size = alloc_size;
		if (par3_ctx->dir_packet == NULL){
			par3_ctx->dir_packet = malloc(alloc_size);
			if (par3_ctx->dir_packet == NULL){
				perror("Failed to allocate memory for Directory Packet");
				return RET_MEMORY_ERROR;
			}
		}
	}

	if (par3_ctx->file_system & 0x10003){	// UNIX Permissions Packet or FAT Permissions Packet
		alloc_size = 0;
		if (par3_ctx->file_system & 3){	// UNIX Permissions Packet
			// Every files and directories may have this optional packet.
			num = par3_ctx->input_file_count + par3_ctx->input_dir_count + absolute_num;
			alloc_size += 84 * num;	// mtime and i_mode are set.
			if (par3_ctx->noise_level >= 2){
				printf("Possible total size of UNIX Permissions Packet = %u\n", 84 * num);
			}
		}
		if (par3_ctx->file_system & 0x10000){	// FAT Permissions Packet
			// Every files may have this optional packet. (exclude directories)
			num = par3_ctx->input_file_count;
			alloc_size += 74 * num;	// LastWriteTimestamp is set.
			if (par3_ctx->noise_level >= 2){
				printf("Possible total size of FAT Permissions Packet = %u\n", 74 * num);
			}
		}
		file_system_alloc_size = alloc_size;
		if (par3_ctx->file_system_packet == NULL){
			par3_ctx->file_system_packet = malloc(alloc_size);
			if (par3_ctx->file_system_packet == NULL){
				perror("Failed to allocate memory for File System Packet");
				return RET_MEMORY_ERROR;
			}
		}
		par3_ctx->file_system_packet_size = 0;
		par3_ctx->file_system_packet_count = 0;
	}

	alloc_size = 48 + 8 + 1 + 4;	// packet header, index, attributes, options
	num = par3_ctx->input_file_count + par3_ctx->input_dir_count;
	alloc_size += 16 * num;	// checksums of File Packets and Directory Packets
	if (par3_ctx->noise_level >= 2){
		printf("Possible total size of Root Packet = %zu\n", alloc_size);
	}
	root_alloc_size = alloc_size;
	if (par3_ctx->root_packet == NULL){
		par3_ctx->root_packet = malloc(alloc_size);
		if (par3_ctx->root_packet == NULL){
			perror("Failed to allocate memory for Root Packet");
			return RET_MEMORY_ERROR;
		}
	}

	// Number of File Packet may be same as number of input files.
	// When there are same files in different directories, deduplication detects them.
	// Deduplication may reduce number of File Packets.
	file_list = par3_ctx->input_file_list;
	packet_count = 0;
	num = par3_ctx->input_file_count;
	if (num > 0){
		uint8_t buf_tail[40];
		uint32_t chunk_index, chunk_num;
		uint64_t block_size, tail_size, total_size;
		PAR3_CHUNK_CTX *chunk_p;

		total_packet_size = 0;
		block_size = par3_ctx->block_size;
		tmp_p = par3_ctx->file_packet;
		file_p = par3_ctx->input_file_list;
		chunk_p = par3_ctx->chunk_list;
		while (num > 0){
			// offset of this packet
			file_p->offset = tmp_p - par3_ctx->file_packet;
			packet_size = 48;
			// Remove sub-directories to store name only.
			name_p = strrchr(file_p->name, '/');
			if (name_p == NULL){	// There is no sub-directory.
				name_p = file_p->name;
			} else {	// When there is sub-directory.
				name_p++;
			}

			// length of filename in bytes
			len = strlen(name_p);
			memcpy(tmp_p + packet_size, &len, 2);
			packet_size += 2;
			// filename
			memcpy(tmp_p + packet_size, name_p, len);
			packet_size += len;
			// hash of the first 16kB of the file
			memcpy(tmp_p + packet_size, &(file_p->crc), 8);
			packet_size += 8;
			// hash of the protected data in the file
			memcpy(tmp_p + packet_size, file_p->hash, 16);
			packet_size += 16;

			// number of options
			option_offset = packet_size;
			option_num = 0;
			packet_size += 1;
			// UNIX Permissions Packet
			if (par3_ctx->file_system & 3){
				if (make_unix_permission_packet(par3_ctx, file_p->name, tmp_p + packet_size) == 0){
					option_num++;
					packet_size += 16;
				}
			}
			// FAT Permissions Packet
			if (par3_ctx->file_system & 0x10000){
				if (make_fat_permission_packet(par3_ctx, file_p->name, tmp_p + packet_size) == 0){
					option_num++;
					packet_size += 16;
				}
			}
			tmp_p[option_offset] = option_num;	// Value is saved in 1-byte.

			if (file_p->size > 0){	// chunk descriptions
				total_size = 0;
				chunk_index = file_p->chunk;
				chunk_num = file_p->chunk_num;
				while (chunk_num > 0){
					// If the first field is zero, it means Unprotected Chunk Description.
					if (chunk_p[chunk_index].size == 0){	// Unprotected Chunk Description
						file_p->state |= 0x80000000;
						// zeros
						memset(tmp_p + packet_size, 0, 8);
						packet_size += 8;
						// length of chunk
						total_size += chunk_p[chunk_index].block;
						memcpy(tmp_p + packet_size, &(chunk_p[chunk_index].block), 8);
						packet_size += 8;

					} else {	// Protected Chunk Description
						// length of protected chunk
						total_size += chunk_p[chunk_index].size;
						memcpy(tmp_p + packet_size, &(chunk_p[chunk_index].size), 8);
						packet_size += 8;
						if (chunk_p[chunk_index].size >= block_size){
							// index of first input block holding chunk
							memcpy(tmp_p + packet_size, &(chunk_p[chunk_index].block), 8);
							packet_size += 8;
							//printf("chunk[%2u], block[%2"PRIu64"], %s\n", chunk_index, chunk_p[chunk_index].index, file_p->name);
						}
						tail_size = chunk_p[chunk_index].size % block_size;
						if (tail_size >= 40){
							// hash of first 40 bytes of tail
							memcpy(tmp_p + packet_size, &(chunk_p[chunk_index].tail_crc), 8);
							packet_size += 8;
							// hash of all of tail
							memcpy(tmp_p + packet_size, chunk_p[chunk_index].tail_hash, 16);
							packet_size += 16;
							// index of block holding tail
							memcpy(tmp_p + packet_size, &(chunk_p[chunk_index].tail_block), 8);
							packet_size += 8;
							// offset of tail inside block
							memcpy(tmp_p + packet_size, &(chunk_p[chunk_index].tail_offset), 8);
							packet_size += 8;
						} else if (tail_size > 0){
							memcpy(buf_tail, &(chunk_p[chunk_index].tail_crc), 8);
							memcpy(buf_tail + 8, chunk_p[chunk_index].tail_hash, 16);
							memcpy(buf_tail + 24, &(chunk_p[chunk_index].tail_block), 8);
							memcpy(buf_tail + 32, &(chunk_p[chunk_index].tail_offset), 8);
							// tail's contents
							memcpy(tmp_p + packet_size, buf_tail, tail_size);
							packet_size += tail_size;
						}
					}

					chunk_index++;	// goto next chunk
					chunk_num--;
				}

				// When all chunks are protected, check total size of chunks.
				if ( ((file_p->state & 0x80000000) == 0) && (total_size != file_p->size) ){
					printf("Error: total size of chunks = %"PRIu64", file size = %"PRIu64"\n", total_size, file_p->size);
					return RET_LOGIC_ERROR;
				}
			}

			// packet header
			make_packet_header(tmp_p, packet_size, par3_ctx->set_id, "PAR FIL\0", 1);
			// Copy checksum of packet for Directory & Root Packet
			memcpy(file_p->chk, tmp_p + 8, 16);

			// Checksum of packet for empty files with same filename may be same.
			// If there is a same checksum already, erase the later duplicated packet.
			max = par3_ctx->input_file_count - num;
			for (i = 0; i < max; i++){
				if ( (file_p->chk[0] == file_list[i].chk[0]) && (file_p->chk[1] == file_list[i].chk[1]) ){
					//printf("find duplicated File Packet ! %u and %u\n", i, max);
					//printf("offset %"PRId64" and %"PRId64"\n", file_list[i].offset, file_p->offset);
					file_p->offset = file_list[i].offset;
					break;
				}
			}
			if (i == max){
				packet_count++;
				tmp_p += packet_size;
				total_packet_size += packet_size;
			}

			file_p++;
			num--;
		}

		if (total_packet_size < file_alloc_size){	// Reduce memory usage to used size.
			tmp_p = realloc(par3_ctx->file_packet, total_packet_size);
			if (tmp_p == NULL){
				perror("Failed to re-allocate memory for File Packet");
				return RET_MEMORY_ERROR;
			}
			par3_ctx->file_packet = tmp_p;
		}
		par3_ctx->file_packet_size = total_packet_size;
		par3_ctx->file_packet_count = packet_count;
		if (par3_ctx->noise_level >= 1){
			printf("Total size of File Packet = %zu (count = %u / %u)\n", total_packet_size, packet_count, par3_ctx->input_file_count);
		}
	}

	// Allocate buffer for children's checksums.
	alloc_size = packet_count + par3_ctx->input_dir_count;
	if (alloc_size < 1)
		alloc_size = 1;
	//printf("Possible number of File Packet and Diretory Packet = %zu\n", alloc_size);
	alloc_size *= 16;	// size of total checksums
	chk_p = malloc(alloc_size);

	// Number of Directory Packet may be same as number of input directories.
	// When there are same empty folder in different directories, there are less packets.
	dir_list = par3_ctx->input_dir_list;
	num = par3_ctx->input_dir_count;
	if (num + absolute_num > 0){
		total_packet_size = 0;
		packet_count = 0;
		tmp_p = par3_ctx->dir_packet;
		dir_p = par3_ctx->input_dir_list;
		while (num > 0){
			// offset of this packet
			dir_p->offset = tmp_p - par3_ctx->dir_packet;
			packet_size = 48;
			// Remove sub-directories to store name only.
			name_p = strrchr(dir_p->name, '/');
			if (name_p == NULL){	// There is no sub-directory.
				name_p = dir_p->name;
			} else {	// When there is sub-directory.
				name_p++;
			}

			// length of string in bytes
			len = strlen(name_p);
			memcpy(tmp_p + packet_size, &len, 2);
			packet_size += 2;
			// name of directory
			memcpy(tmp_p + packet_size, name_p, len);
			packet_size += len;

			// number of options
			option_offset = packet_size;
			option_num = 0;
			packet_size += 4;
			// UNIX Permissions Packet
			if ( ((par3_ctx->file_system & 4) != 0) && ((par3_ctx->file_system & 3) != 0) ){
				if (make_unix_permission_packet(par3_ctx, dir_p->name, tmp_p + packet_size) == 0){
					option_num++;
					packet_size += 16;
				}
			}
			memcpy(tmp_p + option_offset, &option_num, 4);	// Value is saved in 4-bytes.

			// Search children files
			//printf("search children of \"%s\"\n", dir_p->name);
			len = strlen(dir_p->name);
			alloc_size = 0;
			max = par3_ctx->input_file_count;
			for (i = 0; i < max; i++){
				if ((file_list[i].name[len] == '/') && (strncmp(dir_p->name, file_list[i].name, len) == 0)){
					if (strchr(file_list[i].name + len + 1, '/') == NULL){
						//printf("find child F[%2u] \"%s\"\n", i, file_list[i].name);
						memcpy(chk_p + alloc_size, file_list[i].chk, 16);
						alloc_size += 16;
					}
				}
			}
			// Search children directories
			max = par3_ctx->input_dir_count - num;
			for (i = 0; i < max; i++){
				if ((dir_list[i].name[len] == '/') && (strncmp(dir_p->name, dir_list[i].name, len) == 0)){
					if (strchr(dir_list[i].name + len + 1, '/') == NULL){
						//printf("find child D[%2u] \"%s\"\n", i, dir_list[i].name);
						memcpy(chk_p + alloc_size, dir_list[i].chk, 16);
						alloc_size += 16;
					}
				}
			}
			//printf("found children of \"%s\" = %zu\n", dir_p->name, alloc_size / 16);
			if (alloc_size > 16){
				// quick sort
				qsort( (void *)chk_p, alloc_size / 16, 16, compare_checksum );
			}

			// checksums of File and Directory packets
			memcpy(tmp_p + packet_size, chk_p, alloc_size);
			packet_size += alloc_size;

			// packet header
			make_packet_header(tmp_p, packet_size, par3_ctx->set_id, "PAR DIR\0", 1);
			// Copy checksum of packet for Directory & Root Packet
			memcpy(dir_p->chk, tmp_p + 8, 16);

			// Checksum of packet for empty files with same filename may be same.
			// If there is a same checksum already, erase the later duplicated packet.
			max = par3_ctx->input_dir_count - num;
			for (i = 0; i < max; i++){
				if ( (dir_p->chk[0] == dir_list[i].chk[0]) && (dir_p->chk[1] == dir_list[i].chk[1]) ){
					//printf("find duplicated Directory Packet ! %u and %u\n", i, max);
					dir_p->offset = dir_list[i].offset;
					break;
				}
			}
			if (i == max){
				packet_count++;
				tmp_p += packet_size;
				total_packet_size += packet_size;
			}

			dir_p++;
			num--;
		}

		if (absolute_num > 0){	// Add parts of absolute path
			name_p = strrchr(par3_ctx->base_path, '/');
			if (name_p != NULL){
				name_p++;

				packet_size = 48;
				// length of string in bytes
				len = strlen(name_p);
				memcpy(tmp_p + packet_size, &len, 2);
				packet_size += 2;
				// name of directory
				memcpy(tmp_p + packet_size, name_p, len);
				packet_size += len;
				// number of options
				memset(tmp_p + packet_size, 0, 4);
				packet_size += 4;
				// Directories of base path don't store File System Specific Packets.
				// Changing property of parent directories will be a security risk.

				// Search children files (similar to Root Packet's children)
				//printf("search base path's children\n");
				alloc_size = 0;
				max = par3_ctx->input_file_count;
				for (i = 0; i < max; i++){
					if (strchr(file_list[i].name, '/') == NULL){
						//printf("find child F[%2u] \"%s\"\n", i, file_list[i].name);
						memcpy(chk_p + alloc_size, file_list[i].chk, 16);
						alloc_size += 16;
					}
				}
				// Search children directories
				max = par3_ctx->input_dir_count;
				for (i = 0; i < max; i++){
					if (strchr(dir_list[i].name, '/') == NULL){
						//printf("find child D[%2u] \"%s\"\n", i, dir_list[i].name);
						memcpy(chk_p + alloc_size, dir_list[i].chk, 16);
						alloc_size += 16;
					}
				}
				//printf("found base path's children = %zu\n", alloc_size / 16);
				if (alloc_size > 16){
					// quick sort
					qsort( (void *)chk_p, alloc_size / 16, 16, compare_checksum );
				}

				// checksums of File and Directory packets
				memcpy(tmp_p + packet_size, chk_p, alloc_size);
				packet_size += alloc_size;

				// packet header
				make_packet_header(tmp_p, packet_size, par3_ctx->set_id, "PAR DIR\0", 1);
				// Copy checksum of packet for Directory & Root Packet
				memcpy(chk_p, tmp_p + 8, 16);

				packet_count++;
				tmp_p += packet_size;
				total_packet_size += packet_size;

				name_p--;
			}

			// check other directory marks
			while (name_p >= par3_ctx->base_path){
				if ( (name_p[0] == '/') && (name_p > par3_ctx->base_path) )
					name_p--;

				// find next directory mark
				while ( (name_p[0] != '/') && (name_p > par3_ctx->base_path) )
					name_p--;
				if (name_p[0] == '/')
					name_p++;

				if (par3_ctx->absolute_path != 'A'){
					// don't include drive letter on Windows OS
					if ( (name_p[1] == ':') && (name_p[2] == '/') )
						break;
				}

				packet_size = 48;
				// length of string in bytes
				len = 0;
				while (name_p[len] != '/')
					len++;
				memcpy(tmp_p + packet_size, &len, 2);
				packet_size += 2;
				// name of directory
				memcpy(tmp_p + packet_size, name_p, len);
				packet_size += len;
				// number of options
				memset(tmp_p + packet_size, 0, 4);
				packet_size += 4;

				// checksums of Directory packet (sub directory is only one.)
				memcpy(tmp_p + packet_size, chk_p, 16);
				packet_size += 16;

				// packet header
				make_packet_header(tmp_p, packet_size, par3_ctx->set_id, "PAR DIR\0", 1);
				// Copy checksum of packet for Directory & Root Packet
				memcpy(chk_p, tmp_p + 8, 16);

				packet_count++;
				tmp_p += packet_size;
				total_packet_size += packet_size;

				if (name_p > par3_ctx->base_path){
					if (name_p[-1] == '/')
						name_p--;
				}
				if (name_p <= par3_ctx->base_path)
					break;
			}
		}

		if (total_packet_size < dir_alloc_size){	// Reduce memory usage to used size.
			tmp_p = realloc(par3_ctx->dir_packet, total_packet_size);
			if (tmp_p == NULL){
				perror("Failed to re-allocate memory for Directory Packet");
				free(chk_p);
				return RET_MEMORY_ERROR;
			}
			par3_ctx->dir_packet = tmp_p;
		}
		par3_ctx->dir_packet_size = total_packet_size;
		par3_ctx->dir_packet_count = packet_count;
		if (par3_ctx->noise_level >= 1){
			printf("Total size of Directory Packet = %zu (count = %u / %u)\n", total_packet_size, packet_count, par3_ctx->input_dir_count);
		}
	}

	// Root Packet
	tmp_p = par3_ctx->root_packet;
	packet_count = 0;
	packet_size = 48;
	// Lowest unused index for input blocks.
	memcpy(tmp_p + packet_size, &(par3_ctx->block_count), 8);
	packet_size += 8;
	// attributes
	tmp_p[packet_size] = par3_ctx->attribute;
	packet_size += 1;
	// number of options
	memset(tmp_p + packet_size, 0, 4);
	packet_size += 4;
	// This doesn't support packets for options yet.

	if (absolute_num > 0){	// Add parts of absolute path
		alloc_size = 16;
	} else {
		// Search children files
		//printf("search root's children\n");
		alloc_size = 0;
		max = par3_ctx->input_file_count;
		for (i = 0; i < max; i++){
			if (strchr(file_list[i].name, '/') == NULL){
				//printf("find child F[%2u] \"%s\"\n", i, file_list[i].name);
				memcpy(chk_p + alloc_size, file_list[i].chk, 16);
				alloc_size += 16;
			}
		}
		// Search children directories
		max = par3_ctx->input_dir_count;
		for (i = 0; i < max; i++){
			if (strchr(dir_list[i].name, '/') == NULL){
				//printf("find child D[%2u] \"%s\"\n", i, dir_list[i].name);
				memcpy(chk_p + alloc_size, dir_list[i].chk, 16);
				alloc_size += 16;
			}
		}
		//printf("found root's children = %zu\n", alloc_size / 16);
		if (alloc_size > 16){
			// quick sort
			qsort( (void *)chk_p, alloc_size / 16, 16, compare_checksum );
		}
	}
	// checksums of File and Directory packets
	memcpy(tmp_p + packet_size, chk_p, alloc_size);
	packet_size += alloc_size;

	// packet header
	make_packet_header(tmp_p, packet_size, par3_ctx->set_id, "PAR ROO\0", 1);

	if (packet_size < root_alloc_size){	// Reduce memory usage to used size.
		tmp_p = realloc(par3_ctx->root_packet, packet_size);
		if (tmp_p == NULL){
			perror("Failed to re-allocate memory for Root Packet");
			free(chk_p);
			return RET_MEMORY_ERROR;
		}
		par3_ctx->root_packet = tmp_p;
	}
	par3_ctx->root_packet_size = packet_size;
	par3_ctx->root_packet_count = 1;
	if (par3_ctx->noise_level >= 1){
		printf("Size of Root Packet = %zu (children = %zu)\n", packet_size, alloc_size / 16);
	}
	free(chk_p);

	if (par3_ctx->file_system & 0x10003){	// UNIX Permissions Packet or FAT Permissions Packet
		if (par3_ctx->file_system_packet_size == 0){
			free(par3_ctx->file_system_packet);
			par3_ctx->file_system_packet = NULL;
		} else {
			if (par3_ctx->file_system_packet_size < file_system_alloc_size){	// Reduce memory usage to used size.
				tmp_p = realloc(par3_ctx->file_system_packet, par3_ctx->file_system_packet_size);
				if (tmp_p == NULL){
					perror("Failed to re-allocate memory for File System Packet");
					return RET_MEMORY_ERROR;
				}
				par3_ctx->file_system_packet = tmp_p;
			}
			if (par3_ctx->noise_level >= 1){
				printf("Size of File System Packet = %zu (count = %u)\n", par3_ctx->file_system_packet_size, par3_ctx->file_system_packet_count);
			}
		}
	}

	return 0;
}

// External Data Packet
int make_ext_data_packet(PAR3_CTX *par3_ctx)
{
	uint8_t *tmp_p;
	size_t write_packet_count, packet_size;
	int64_t find_block_count;	// use sign for flag
	uint64_t block_count, block_size;
	PAR3_BLOCK_CTX *block_p;

	// When there is no input blocks, just exit.
	if (par3_ctx->block_count == 0)
		return 0;

	// When there is no packet yet, error exit.
	if (par3_ctx->start_packet_size == 0)
		return RET_LOGIC_ERROR;

	// When there is packet already, just exit.
	if (par3_ctx->ext_data_packet_size > 0)
		return 0;

	// Count how many packets to make.
	block_count = par3_ctx->block_count;
	block_size = par3_ctx->block_size;
	block_p = par3_ctx->block_list;
	//printf("Number of input blocks = %"PRIu64"\n", block_count);
	find_block_count = 0;
	write_packet_count = 0;
	while (block_count > 0){
		if (block_p->state & 1){	// block of full size data
			if (find_block_count < 0)
				find_block_count *= -1;
			find_block_count++;
		} else {	// block of chunk tail
			if (find_block_count > 0){	// after full block
				find_block_count *= -1;
				write_packet_count++;
			}
		}

		block_count--;
		block_p++;
	}
	if (find_block_count > 0){	// after full block
		write_packet_count++;
	} else {
		find_block_count *= -1;
	}

	// If there is no full size blocks, checksums are saved in File Packets.
	if (par3_ctx->noise_level >= 2){
		printf("Number of External Data Packet = %zu (number of full size blocks = %"PRId64")\n", write_packet_count, find_block_count);
	}
	if (write_packet_count == 0)
		return 0;

	// Calculate total size of packets
	packet_size = write_packet_count * (48 + 8);	// packet header (48-bytes) + index (8-bytes)
	packet_size += find_block_count * 24;	// CRC-64 + BLAKE3 (24-bytes) per full size blocks
	if (par3_ctx->noise_level >= 1){
		printf("Total size of External Data Packet = %zu\n", packet_size);
	}
	if (par3_ctx->ext_data_packet == NULL){
		par3_ctx->ext_data_packet = malloc(packet_size);
		if (par3_ctx->ext_data_packet == NULL){
			perror("Failed to allocate memory for External Data Packet");
			return RET_MEMORY_ERROR;
		}
	}
	par3_ctx->ext_data_packet_size = packet_size;
	par3_ctx->ext_data_packet_count = (uint32_t)write_packet_count;

	// Copy checksums
	block_count = par3_ctx->block_count;
	block_p = par3_ctx->block_list;
	tmp_p = par3_ctx->ext_data_packet;
	find_block_count = 0;
	write_packet_count = 0;
	while (block_count > 0){
		if (block_p->state & 1){	// block of full size data
			if (write_packet_count == 0){
				tmp_p += 48;	// skip packet header
				memcpy(tmp_p, &find_block_count, 8);	// Index of the first input block
				tmp_p += 8;
			}
			memcpy(tmp_p, &(block_p->crc), 8);	// rolling hash
			tmp_p += 8;
			memcpy(tmp_p, block_p->hash, 16);	// 16-byte fingerprint hash
			tmp_p += 16;
			write_packet_count++;
		} else {	// block of chunk tail
			if (write_packet_count > 0){	// after full block
				// make packet header
				packet_size = 48 + 8 + write_packet_count * 24;
				make_packet_header(tmp_p - packet_size, packet_size, par3_ctx->set_id, "PAR EXT\0", 1);
				write_packet_count = 0;
			}
		}

		find_block_count++;
		block_count--;
		block_p++;
	}
	if (write_packet_count > 0){	// after full block
		// make packet header
		packet_size = 48 + 8 + write_packet_count * 24;
		make_packet_header(tmp_p - packet_size, packet_size, par3_ctx->set_id, "PAR EXT\0", 1);
	}

	return 0;
}

// Duplicate common packets between PAR3 files
int duplicate_common_packet(PAR3_CTX *par3_ctx)
{
	uint8_t *tmp_p;
	size_t packet_size, packet_count;

	// When there is no packet yet, error exit.
	if (par3_ctx->start_packet_size == 0)
		return RET_LOGIC_ERROR;

	// When there are packets already, just exit.
	if (par3_ctx->common_packet_size > 0)
		return 0;

	// Creator Packet and Comment Packet are not repeated.
	// Other important optional packets may be included in future.
	packet_size = par3_ctx->start_packet_size + par3_ctx->matrix_packet_size
			+ par3_ctx->file_packet_size + par3_ctx->dir_packet_size + par3_ctx->root_packet_size
			+ par3_ctx->ext_data_packet_size + par3_ctx->file_system_packet_size;

	if (par3_ctx->common_packet == NULL){
		par3_ctx->common_packet = malloc(packet_size);
		if (par3_ctx->common_packet == NULL){
			perror("Failed to allocate memory for duplicated packets");
			return RET_MEMORY_ERROR;
		}
	}

	// Copy packets
	tmp_p = par3_ctx->common_packet;
	memcpy(tmp_p, par3_ctx->start_packet, par3_ctx->start_packet_size);
	tmp_p += par3_ctx->start_packet_size;
	packet_count = 1;
	if (par3_ctx->matrix_packet_size > 0){
		memcpy(tmp_p, par3_ctx->matrix_packet, par3_ctx->matrix_packet_size);
		tmp_p += par3_ctx->matrix_packet_size;
		packet_count += par3_ctx->matrix_packet_count;
	}
	if (par3_ctx->file_packet_size > 0){
		memcpy(tmp_p, par3_ctx->file_packet, par3_ctx->file_packet_size);
		tmp_p += par3_ctx->file_packet_size;
		packet_count += par3_ctx->file_packet_count;
	}
	if (par3_ctx->dir_packet_size > 0){
		memcpy(tmp_p, par3_ctx->dir_packet, par3_ctx->dir_packet_size);
		tmp_p += par3_ctx->dir_packet_size;
		packet_count += par3_ctx->dir_packet_count;
	}
	// Root Packet exists always.
	memcpy(tmp_p, par3_ctx->root_packet, par3_ctx->root_packet_size);
	tmp_p += par3_ctx->root_packet_size;
	packet_count++;
	if (par3_ctx->ext_data_packet_size > 0){
		memcpy(tmp_p, par3_ctx->ext_data_packet, par3_ctx->ext_data_packet_size);
		tmp_p += par3_ctx->ext_data_packet_size;
		packet_count += par3_ctx->ext_data_packet_count;
	}
	// Optional packets
	if (par3_ctx->file_system_packet_size > 0){
		memcpy(tmp_p, par3_ctx->file_system_packet, par3_ctx->file_system_packet_size);
		tmp_p += par3_ctx->file_system_packet_size;
		packet_count += par3_ctx->file_system_packet_count;
	}

	par3_ctx->common_packet_size = packet_size;
	par3_ctx->common_packet_count = packet_count;

	if (par3_ctx->noise_level >= 1){
		printf("\nTotal size of common packets = %zu (count = %zu)\n", packet_size, packet_count);
	}

	return 0;
}

