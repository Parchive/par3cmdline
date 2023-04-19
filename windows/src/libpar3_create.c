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


int par3_trial(PAR3_CTX *par3_ctx)
{
	int ret;
	uint64_t total_par_size;	// Total size of Index File, Archive Files, and Recovery Files.

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
	total_par_size = try_index_file(par3_ctx);

	// Try other PAR3 files
	if ( (par3_ctx->block_count > 0) && ( (par3_ctx->data_packet != 0) || (par3_ctx->recovery_block_count > 0) ) ){
		ret = duplicate_common_packet(par3_ctx);
		if (ret != 0)
			return ret;

		// Write PAR3 files with input blocks
		if (par3_ctx->data_packet != 0){
			ret = try_archive_file(par3_ctx, &total_par_size);
			if (ret != 0)
				return ret;
		}

		// Write PAR3 files with recovery blocks
		if (par3_ctx->recovery_block_count > 0){
			ret = try_recovery_file(par3_ctx, &total_par_size);
			if (ret != 0)
				return ret;
		}
	}

	// Show efficiency rate
	if (par3_ctx->noise_level >= -1){
		double rate1, rate2;
		// rate1 "File data in Source blocks" = "total size of input file data" / "total size of source blocks"
		// rate2 "Recovery data in PAR files" = "total size of recovery blocks" / "total size of PAR files"
		// rate of "Efficiency of PAR files" = rate1 * rate2
		printf("\nTotal size of PAR files = %I64u\n", total_par_size);
		if ( (par3_ctx->block_count == 0) || (total_par_size == 0) ){
			rate1 = 0;
			rate2 = 0;
		} else {
			// Tiny chunk tails (1~39 bytes) don't consume blocks.
			// Duplicate data reuses same blocks.
			// Sum using bytes in every blocks to calculate total file data size.
			uint64_t block_count, total_data_size;
			PAR3_BLOCK_CTX *block_p;

			block_count = par3_ctx->block_count;
			block_p = par3_ctx->block_list;
			total_data_size = 0;
			while (block_count > 0){
				total_data_size += block_p->size;
				block_p++;
				block_count--;
			}
			//printf("Total file data in input blocks = %I64u\n", total_data_size);

			rate1 = (double)total_data_size / (double)(par3_ctx->block_size * par3_ctx->block_count);
			if (par3_ctx->data_packet != 0){	// Archive Files are same as 100% redundancy.
				rate2 = (double)(total_data_size + par3_ctx->block_size * par3_ctx->recovery_block_count) / (double)total_par_size;
			} else {
				rate2 = (double)(par3_ctx->block_size * par3_ctx->recovery_block_count) / (double)total_par_size;
			}
		}
		// Truncate two decimal places (use integer instead of showing double directly)
		//printf("rate1 = %f, rate2 = %f\n", rate1, rate2);
		ret = (int)(rate1 * 1000);
		printf("File data in Source blocks = %d.%d%%\n", ret / 10, ret % 10);
		ret = (int)(rate2 * 1000);
		printf("Recovery data in PAR files = %d.%d%%\n", ret / 10, ret % 10);
		ret = (int)(rate1 * rate2 * 1000);
		printf("Efficiency of PAR files    = %d.%d%%\n", ret / 10, ret % 10);
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
			if (ret != 0){
				//remove_recovery_file(par3_ctx);	// Remove partially created files
				return ret;
			}
		}

		// When recovery blocks were not created yet, calculate and write at here.
		if ((par3_ctx->ecc_method & 0x8000) == 0){
			if ( (par3_ctx->ecc_method & 8) && (par3_ctx->interleave > 0) ){
				// Interleaving is adapted only for FFT based Reed-Solomon Codes.
				ret = create_recovery_block_cohort(par3_ctx);
			} else {
				ret = create_recovery_block_split(par3_ctx);
			}
			if (ret != 0){
				//remove_recovery_file(par3_ctx);	// Remove partially created files
				return ret;
			}
		}
	}

	return 0;
}

