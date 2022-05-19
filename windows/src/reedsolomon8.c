
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "galois.h"


// Gaussian elimination for Cauchy Reed-Solomon
int rs8_gaussian_elimination(PAR3_CTX *par3_ctx, int lost_count)
{
	uint8_t *matrix;
	int x, y, y_R, y2;
	int *gf_table, *lost_id, *recv_id;
	int block_count, total_count, region_count;
	int pivot, factor, factor2;

	block_count = (int)(par3_ctx->block_count);
	gf_table = par3_ctx->galois_table;
	lost_id = par3_ctx->id_list;
	recv_id = lost_id + lost_count;
	total_count = block_count + lost_count;
	region_count = (total_count + 7) & ~7;

	// Allocate matrix on memory
	matrix = malloc(region_count * lost_count);
	if (matrix == NULL){
		printf("Failed to allocate memory for matrix\n");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->matrix = matrix;

	// Set matrix elements
	for (y = 0; y < lost_count; y++){	// per each recovery block
		// Left side
		y_R = 255 - recv_id[y];	// y_R = MAX - y_index
		for (x = 0; x < block_count; x++){
			// inv( x_index ^ y_R )
			matrix[region_count * y + x] = gf8_reciprocal(gf_table, x ^ y_R);
		}

		// Right side
		for (x = 0; x < lost_count; x++){
			if (x == y){
				factor = 1;
			} else {
				factor = 0;
			}
			matrix[region_count * y + block_count + x] = factor;
		}
	}

	if (par3_ctx->noise_level >= 2){
		printf("\n generator matrix (%d * %d):\n", total_count, lost_count);
		for (y = 0; y < lost_count; y++){
			printf("lost%3d <- recv%3d =", lost_id[y], recv_id[y]);
			for (x = 0; x < block_count; x++){
				printf(" %2x", matrix[region_count * y + x]);
			}
			printf(" |");
			for (x = block_count; x < total_count; x++){
				printf(" %2x", matrix[region_count * y + x]);
			}
			printf("\n");
		}
	}

	// Gaussian elimination
	for (y = 0; y < lost_count; y++){
		// Let pivot value to be 1.
		pivot = lost_id[y];
		factor = matrix[region_count * y + pivot];
		if (factor == 0){
			printf("Failed to invert matrix\n");
			return RET_LOGIC_ERROR;
		}
		factor = gf8_reciprocal(gf_table, factor);
		gf8_region_multiply(gf_table, matrix + region_count * y, factor, total_count, NULL, 0);

		// Erase values of same pivot on other rows.
		for (y2 = 0; y2 < lost_count; y2++){
			if (y2 == y)
				continue;

			factor2 = matrix[region_count * y2 + pivot];
			gf8_region_multiply(gf_table, matrix + region_count * y, factor2, total_count, matrix + region_count * y2, 1);
		}
	}

	if (par3_ctx->noise_level >= 2){
		printf("\n recovery matrix (%d * %d):\n", total_count, lost_count);
		for (y = 0; y < lost_count; y++){
			printf("recv%3d -> lost%3d =", recv_id[y], lost_id[y]);
			for (x = 0; x < block_count; x++){
				printf(" %2x", matrix[region_count * y + x]);
			}
			printf(" |");
			for (x = block_count; x < total_count; x++){
				printf(" %2x", matrix[region_count * y + x]);
			}
			printf("\n");
		}
	}

	return 0;
}

