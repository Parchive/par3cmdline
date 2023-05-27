// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "libpar3.h"
#include "inside.h"
#include "common.h"
#include "map.h"
#include "packet.h"
#include "block.h"
#include "write.h"


static uint64_t initial_block_size(uint64_t data_size)
{
	uint64_t block_size;
	long double f;

	if (data_size <= 40)
		return 40;

	// Let block count to be 1% of block size.
	f = (long double)data_size;
	f = sqrtl(f) * 10;
	block_size = (uint64_t)f;

	// If number of blocks is very few, return the minimum size.
	// Because it creates at least 1 recovery block, number of input blocks should be more than 100.
	if (data_size / block_size < 128)
		block_size = next_pow2(data_size / 256);
	if (block_size <= 40)
		return 40;

	// Block size is good to be power of 2.
	block_size = next_pow2(block_size);

	// 1000 blocks would be enough to protect a file.
	while (data_size / block_size > 2048){
		block_size *= 2;
	}

	return block_size;
}

// Insert PAR3 packets in ZIP file
int par3_insert_zip(PAR3_CTX *par3_ctx, char command_trial)
{
	int ret, format_type, copy_size;
	int repeat_count, best_repeat_count;
	uint64_t original_file_size;
	uint64_t block_size, best_block_size;
	uint64_t block_count, best_block_count;
	uint64_t recv_block_count, best_recv_block_count;
	uint64_t total_packet_size, best_total_size;

	ret = check_outside_format(par3_ctx, &format_type, &copy_size);
	if (ret != 0)
		return ret;

	//printf("ecc_method = %x\n", par3_ctx->ecc_method);
	par3_ctx->ecc_method = 1;	// At this time, select Cauchy Reed-Solomon Codes by default.

	original_file_size = par3_ctx->total_file_size;
	block_size = initial_block_size(original_file_size);
/*
	// to test rare case for debug
	block_size = 150;
	copy_size = 350;
*/
	if (par3_ctx->noise_level >= 1){
		printf("\nTesting block size from %I64d:\n\n", block_size);
	}
	best_block_size = block_size;
	best_total_size = inside_zip_size(par3_ctx, block_size, copy_size, &best_block_count, &best_recv_block_count, &best_repeat_count);
	if (block_size == 40){
		block_size = 64;
	} else {
		block_size *= 2;
	}
	while (block_size * 2 <= original_file_size){	// Try to find better block size
		total_packet_size = inside_zip_size(par3_ctx, block_size, copy_size, &block_count, &recv_block_count, &repeat_count);
		// When the difference is very small (like 1.6%), selecting more blocks would be safe.
		// (original_file_size + total_packet_size) < (original_file_size + best_total_size) * 63 / 64
		if ((original_file_size + total_packet_size) * 64 < (original_file_size + best_total_size) * 63){
		//if (total_packet_size < best_total_size){
			best_total_size = total_packet_size;
			best_block_size = block_size;
			best_block_count = block_count;
			best_recv_block_count = recv_block_count;
			best_repeat_count = repeat_count;
		} else {
			break;
		}
		block_size *= 2;
	}
	par3_ctx->block_size = best_block_size;
	par3_ctx->block_count = best_block_count;
	par3_ctx->recovery_block_count = best_recv_block_count;
	par3_ctx->max_recovery_block = best_recv_block_count;
	repeat_count = best_repeat_count;
	if (par3_ctx->noise_level >= 1){
		printf("Best block size = %I64d\nblock count = %I64d, recvory block count = %I64d, repeat count = %d\n",
				best_block_size, best_block_count, best_recv_block_count, repeat_count);
	}

	if (command_trial != 0){
		// Show efficiency rate
		if (par3_ctx->noise_level >= -1){
			double rate;
			// rate of "Additional PAR data" = "additional data size" / "original file size"
			// rate of "Redundancy in blocks" = "number of recovery blocks" / "number of input blocks"
			// rate of "Efficiency of PAR data" = "total size of recovery blocks" / "additional data size"
			printf("\nSize of Outside file = %I64u\n", original_file_size + best_total_size + copy_size);
			// Truncate two decimal places (use integer instead of showing double directly)
			//printf("rate1 = %f, rate2 = %f\n", rate1, rate2);
			rate = (double)(best_total_size + copy_size) / (double)original_file_size;
			ret = (int)(rate * 1000);
			printf("Additional PAR data    = %d.%d%%\n", ret / 10, ret % 10);
			rate = (double)best_recv_block_count / (double)best_block_count;
			ret = (int)(rate * 1000);
			printf("Redundancy of blocks   = %d.%d%%\n", ret / 10, ret % 10);
			rate = (double)(best_block_size * best_recv_block_count) / (double)(best_total_size + copy_size);
			ret = (int)(rate * 1000);
			printf("Efficiency of PAR data = %d.%d%%\n", ret / 10, ret % 10);
		}
		return 0;
	}

	// Map input file slices into input blocks.
	if (format_type == 2){	// ZIP (.zip)
		// It splits original file into 2 chunks and appends 2 chunks.
		// [ data chunk ] [ footer chunk ] [ unprotected chunk ] [ duplicated footer chunk ]
		if (par3_ctx->noise_level >= 2){
			printf("ZIP file format (.zip)\n");
		}
		// Special funtion is required for additonal chunks.
		ret = map_input_block_zip(par3_ctx, copy_size, best_total_size);

	} else if (format_type == 3){	// 7-Zip (.7z)
		// It appends 1 chunk.
		// [ protected chunk ] [ unprotected chunk ]
		if (par3_ctx->noise_level >= 2){
			printf("7-Zip file format (.7z)\n");
		}
		ret = map_input_block_zip(par3_ctx, 0, best_total_size);

	} else {
		ret = RET_LOGIC_ERROR;
	}
	if (ret != 0)
		return ret;

	// Creator Packet, Comment Packet, Start Packet
	ret = make_start_packet(par3_ctx, 0);
	if (ret != 0)
		return ret;

	// Matrix Packet
	ret = make_matrix_packet(par3_ctx);
	if (ret != 0)
		return ret;

	// File Packet, Directory Packet, Root Packet
	ret = make_file_packet(par3_ctx);
	if (ret != 0)
		return ret;

	// External Data Packet
	ret = make_ext_data_packet(par3_ctx);
	if (ret != 0)
		return ret;

	ret = duplicate_common_packet(par3_ctx);
	if (ret != 0)
		return ret;

	// When it uses Reed-Solomon Erasure Codes, it tries to keep all recovery blocks on memory.
	if (par3_ctx->ecc_method & 1){
		ret = allocate_recovery_block(par3_ctx);
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

	// Insert space (unprotected chunks) into outside file
	ret = insert_space_zip(par3_ctx, copy_size, repeat_count);
	if (ret != 0)
		return ret;

	// When recovery blocks were not created yet, calculate and write at here.
	if ((par3_ctx->ecc_method & 0x8000) == 0){
		ret = create_recovery_block_split(par3_ctx);
		if (ret != 0)
			return ret;
	}

	return 0;
}

// Delete PAR3 packets from ZIP file
int par3_delete_zip(PAR3_CTX *par3_ctx)
{
	int ret;

	ret = delete_inside_data(par3_ctx);
	if (ret != 0)
		return ret;

	return 0;
}

