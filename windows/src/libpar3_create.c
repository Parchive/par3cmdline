// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "map.h"
#include "packet.h"
#include "write.h"
#include "block.h"


// add text in Creator Packet
int add_creator_text(PAR3_CTX *par3_ctx, char *text)
{
	uint8_t *tmp_p;
	size_t len, alloc_size;

	len = strlen(text);
	if (len == 0)
		return 0;

	if (par3_ctx->creator_packet == NULL){	// When there is no packet yet, allocate now.
		alloc_size = 48 + len;
		par3_ctx->creator_packet = malloc(alloc_size);
		if (par3_ctx->creator_packet == NULL){
			perror("Failed to allocate memory for Creator Packet");
			return RET_MEMORY_ERROR;
		}
	} else {	// When there is packet already, add new text to previous text.
		alloc_size = par3_ctx->creator_packet_size + len;
		tmp_p = realloc(par3_ctx->creator_packet, alloc_size);
		if (tmp_p == NULL){
			perror("Failed to re-allocate memory for Creator Packet");
			return RET_MEMORY_ERROR;
		}
		par3_ctx->creator_packet = tmp_p;
	}
	par3_ctx->creator_packet_size = alloc_size;
	memcpy(par3_ctx->creator_packet + alloc_size - len, text, len);
	par3_ctx->creator_packet_count = 1;

	return 0;
}

// add text in Comment Packet
int add_comment_text(PAR3_CTX *par3_ctx, char *text)
{
	uint8_t *tmp_p;
	size_t len, alloc_size;

	// If text is covered by ", remove them.
	len = strlen(text);
	if ( (len > 2) && (text[0] == '"') && (text[len - 1] == '"') ){
		text++;
		len -= 2;
	}
	if (len == 0)
		return 0;

	if (par3_ctx->comment_packet == NULL){	// When there is no packet yet, allocate now.
		alloc_size = 48 + len;
		par3_ctx->comment_packet = malloc(alloc_size);
		if (par3_ctx->comment_packet == NULL){
			perror("Failed to allocate memory for Comment Packet");
			return RET_MEMORY_ERROR;
		}
	} else {	// When there is packet already, add new comment to previous comment.
		alloc_size = par3_ctx->comment_packet_size + 1 + len;
		tmp_p = realloc(par3_ctx->comment_packet, alloc_size);
		if (tmp_p == NULL){
			perror("Failed to re-allocate memory for Comment Packet");
			return RET_MEMORY_ERROR;
		}
		par3_ctx->comment_packet = tmp_p;
		tmp_p += par3_ctx->comment_packet_size;
		tmp_p[0] = '\n';	// Put "\n" between comments.
	}
	par3_ctx->comment_packet_size = alloc_size;
	memcpy(par3_ctx->comment_packet + alloc_size - len, text, len);
	par3_ctx->comment_packet_count = 1;

	return 0;
}


// Calculate creating amount of recovery blocks from given redundancy.
static int calculate_recovery_count(PAR3_CTX *par3_ctx)
{
	uint64_t total_count;

	if (par3_ctx->block_count == 0){
		par3_ctx->redundancy_size = 0;
		par3_ctx->recovery_block_count = 0;
		return 0;	// There is no input block.
	}
	if ( (par3_ctx->recovery_block_count == 0) && (par3_ctx->redundancy_size == 0) )
		return 0;	// Not specified

	// When number of recovery blocks was not specified, set by redundancy.
	if ( (par3_ctx->recovery_block_count == 0) && (par3_ctx->redundancy_size > 0) ){
		// If redundancy_size is in range (0 ~ 250), it's a percent rate value.
		// When there is remainder at division, round up the quotient.
		par3_ctx->recovery_block_count = (par3_ctx->block_count * par3_ctx->redundancy_size + 99) / 100;
	}

	// Test number of blocks
	if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
		if (par3_ctx->noise_level >= 0){
			printf("FFT based Reed-Solomon Codes\n");
		}
		total_count = par3_ctx->block_count + par3_ctx->first_recovery_block + par3_ctx->recovery_block_count;
		if (total_count < par3_ctx->block_count + par3_ctx->max_recovery_block)
			total_count = par3_ctx->block_count + par3_ctx->max_recovery_block;
		if (total_count > 65536){
			printf("Total block count %I64u are too many.\n", total_count);
			return RET_LOGIC_ERROR;
		}
		// Leopard-RS library has a restriction; recovery_count <= 32768
		// It seems to be possible to solve this problem.
		// But, I don't try at this time.
		total_count = par3_ctx->first_recovery_block + par3_ctx->recovery_block_count;
		if (total_count < par3_ctx->max_recovery_block)
			total_count = par3_ctx->max_recovery_block;
		if (total_count > 32768){
			printf("Recovery block count %I64u are too many.\n", total_count);
			return RET_LOGIC_ERROR;
		}

	} else {	// Cauchy Reed-Solomon Codes
		if (par3_ctx->noise_level >= 0){
			printf("Cauchy Reed-Solomon Codes\n");
		}
		total_count = par3_ctx->block_count + par3_ctx->first_recovery_block + par3_ctx->recovery_block_count;
		if (total_count < par3_ctx->block_count + par3_ctx->max_recovery_block)
			total_count = par3_ctx->block_count + par3_ctx->max_recovery_block;
		if (total_count > 65536){
			printf("Total block count %I64u are too many.\n", total_count);
			return RET_LOGIC_ERROR;
		}
	}

	if (par3_ctx->noise_level >= 0){
		printf("Recovery block count = %I64u\n", par3_ctx->recovery_block_count);
		if (par3_ctx->max_recovery_block > 0){
			printf("Max recovery block count = %I64u\n", par3_ctx->max_recovery_block);
		}
	}

	return 0;
}


int par3_trial(PAR3_CTX *par3_ctx)
{
	int ret;

	// Load input blocks on memory.
	if (par3_ctx->block_count == 0){
		ret = map_chunk_tail(par3_ctx);
	} else if (par3_ctx->deduplication == '1'){	// Simple deduplication
		ret = map_input_block(par3_ctx);
	} else if (par3_ctx->deduplication == '2'){	// Deduplication with slide search
		ret = map_input_block_slide(par3_ctx);
	} else {
		// Because this doesn't read file data, InputSetID will differ.
		ret = map_input_block_trial(par3_ctx);

		// This is for debug.
		// When no deduplication, no need to read input files in trial.
//		ret = map_input_block_simple(par3_ctx);
	}
	if (ret != 0)
		return ret;

	// Call this function before creating Start Packet.
	ret = calculate_recovery_count(par3_ctx);
	if (ret != 0)
		return ret;

	// Creator Packet, Comment Packet, Start Packet
	ret = make_start_packet(par3_ctx, 1);
	if (ret != 0)
		return ret;

	// Only when recovery blocks will be created, make Matrix Packet.
	if (par3_ctx->recovery_block_count > 0){
		ret = make_matrix_packet(par3_ctx);
		if (ret != 0)
			return ret;
	}

	// File Packet, Directory Packet, Root Packet
	ret = make_file_packet(par3_ctx);
	if (ret != 0)
		return ret;

	// External Data Packet
	ret = make_ext_data_packet(par3_ctx);
	if (ret != 0)
		return ret;

	// Try Index File
	try_index_file(par3_ctx);

	// Try PAR3 files with input blocks
	if ( (par3_ctx->block_count > 0) && ( (par3_ctx->data_packet != 0) || (par3_ctx->recovery_block_count > 0) ) ){
		ret = duplicate_common_packet(par3_ctx);
		if (ret != 0)
			return ret;

		// Write PAR3 files with input blocks
		if (par3_ctx->data_packet != 0){
			ret = try_archive_file(par3_ctx);
			if (ret != 0)
				return ret;
		}

		// Write PAR3 files with recovery blocks
		if (par3_ctx->recovery_block_count > 0){
			ret = try_recovery_file(par3_ctx);
			if (ret != 0)
				return ret;
		}
	}

	return 0;
}

int par3_create(PAR3_CTX *par3_ctx)
{
	int ret;

	// Load input blocks on memory.
	if (par3_ctx->block_count == 0){
		ret = map_chunk_tail(par3_ctx);
	} else if (par3_ctx->deduplication == '1'){	// Simple deduplication
		ret = map_input_block(par3_ctx);
	} else if (par3_ctx->deduplication == '2'){	// Deduplication with slide search
		ret = map_input_block_slide(par3_ctx);
	} else {
		ret = map_input_block_simple(par3_ctx);
	}
	if (ret != 0)
		return ret;

	// Call this function before creating Start Packet.
	ret = calculate_recovery_count(par3_ctx);
	if (ret != 0)
		return ret;

	// Creator Packet, Comment Packet, Start Packet
	ret = make_start_packet(par3_ctx, 0);
	if (ret != 0)
		return ret;

	// Only when recovery blocks will be created, make Matrix Packet.
	if (par3_ctx->recovery_block_count > 0){
		ret = make_matrix_packet(par3_ctx);
		if (ret != 0)
			return ret;
	}

	// File Packet, Directory Packet, Root Packet
	ret = make_file_packet(par3_ctx);
	if (ret != 0)
		return ret;

	// External Data Packet
	ret = make_ext_data_packet(par3_ctx);
	if (ret != 0)
		return ret;

	// Write Index File
	ret = write_index_file(par3_ctx);
	if (ret != 0)
		return ret;

	// Write other PAR3 files
	if ( (par3_ctx->block_count > 0) && ( (par3_ctx->data_packet != 0) || (par3_ctx->recovery_block_count > 0) ) ){
		ret = duplicate_common_packet(par3_ctx);
		if (ret != 0)
			return ret;

		// When it uses Reed-Solomon Erasure Codes, it tries to keep all recovery blocks on memory.
		if (par3_ctx->ecc_method & 1){
			ret = allocate_recovery_block(par3_ctx);
			if (ret != 0)
				return ret;
		}

		// Write PAR3 files with input blocks
		if (par3_ctx->data_packet != 0){
			ret = write_archive_file(par3_ctx);
			if (ret != 0)
				return ret;
		}

		// If there are enough memory to keep all recovery blocks,
		// it calculates recovery blocks before writing Recovery Data Packets.
		if (par3_ctx->ecc_method & 0x8000){
			ret = create_recovery_block(par3_ctx);
			if (ret < 0){
				par3_ctx->ecc_method &= ~0x8000;
			} else if (ret > 0){
				return ret;
			}
		}

		// Write PAR3 files with recovery blocks
		if (par3_ctx->recovery_block_count > 0){
			ret = write_recovery_file(par3_ctx);
			if (ret != 0)
				return ret;
		}

		// When recovery blocks were not created yet, calculate and write at here.
		if ((par3_ctx->ecc_method & 0x8000) == 0){
			ret = create_recovery_block_split(par3_ctx);
			if (ret != 0)
				return ret;
		}
	}

	return 0;
}

