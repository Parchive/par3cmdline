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

	// 3000 blocks would be enough to protect a file.
	while (data_size / block_size > 8192){
		block_size *= 2;
	}

	return block_size;
}

// Insert PAR3 packets to ZIP file
int par3_insert_zip(PAR3_CTX *par3_ctx)
{
	int ret, format_type;
	uint32_t copy_size;
	uint64_t original_file_size;
	uint64_t block_size, best_block_size;
	uint64_t total_packet_size, best_total_size;

	ret = check_outside_format(par3_ctx, &format_type, &copy_size);
	if (ret != 0)
		return ret;

	original_file_size = par3_ctx->total_file_size;
	block_size = initial_block_size(original_file_size);
	if (par3_ctx->noise_level >= 2){
		printf("Start block size = %I64d\n\n", block_size);
	}
	best_block_size = block_size;
	best_total_size = inside_zip_size(par3_ctx, block_size, copy_size);
	if (block_size == 40){
		block_size = 64;
	} else {
		block_size *= 2;
	}
	while (block_size * 2 <= original_file_size){
		total_packet_size = inside_zip_size(par3_ctx, block_size, copy_size);
		// When the difference is very small, selecting more blocks would be safe.
		// total_packet_size < best_total_size * 99 / 100
		//if (total_packet_size * 100 < best_total_size * 99){
		if (total_packet_size < best_total_size){
			best_total_size = total_packet_size;
			best_block_size = block_size;
		} else {
			break;
		}
		block_size *= 2;
	}
	block_size = best_block_size;
	printf("Best block size = %I64d\n\n", block_size);


	return 0;
}

// Delete PAR3 packets from ZIP file
int par3_delete_zip(PAR3_CTX *par3_ctx)
{



	return 0;
}

