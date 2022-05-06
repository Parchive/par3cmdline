
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "galois.h"


// Create all recovery blocks from one input block.
void rs_create_one_all(PAR3_CTX *par3_ctx, int x_index)
{
	uint8_t *work_buf, *buf_p;
	int *gf_table;
	int first_num, element;
	int y_index, y_R;
	int recovery_block_count;
	size_t region_size;

	recovery_block_count = (int)(par3_ctx->recovery_block_count);
	first_num = (int)(par3_ctx->first_recovery_block);
	gf_table = par3_ctx->galois_table;
	work_buf = par3_ctx->work_buf;
	buf_p = par3_ctx->recovery_data;

	// For every recovery block
	region_size = (par3_ctx->block_size + 1 + 7) & ~8;
	for (y_index = 0; y_index < recovery_block_count; y_index++){
		// Calculate Matrix elements
		if (par3_ctx->galois_poly == 0x1100B){	// 16-bit Galois Field
			y_R = 65535 - (y_index + first_num);


		} else {	// 8-bit Galois Field
			y_R = 255 - (y_index + first_num);
			element = gf8_reciprocal(gf_table, x_index ^ y_R);	// inv( x_index ^ y_R )

			// If x_index == 0, just put values.
			// If x_index > 0, add values on previous values.
			gf8_region_multiply(gf_table, work_buf, element, region_size, buf_p, x_index);
			buf_p += region_size;
		}
		//printf("x = %d, R = %d, y_R = %d, element = %d\n", x_index, y_index + first_num, y_R, element);
	}
}

