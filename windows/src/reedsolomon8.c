
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "galois.h"


// Gaussian elimination of matrix for Cauchy Reed-Solomon
int rs8_gaussian_elimination(PAR3_CTX *par3_ctx, int lost_count)
{
	uint8_t *gf_table, *matrix;
	int x, y, y_R, y2;
	int *lost_id, *recv_id;
	int block_count;
	int pivot, factor, factor2;

	block_count = (int)(par3_ctx->block_count);
	gf_table = par3_ctx->galois_table;
	lost_id = par3_ctx->id_list;
	recv_id = lost_id + lost_count;

	// Allocate matrix on memory
	matrix = malloc(block_count * lost_count);
	if (matrix == NULL){
		printf("Failed to allocate memory for matrix\n");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->matrix = matrix;

	// Set matrix elements
	for (y = 0; y < lost_count; y++){	// per each recovery block
		// These are elements of generator matrix.
		y_R = 255 - recv_id[y];	// y_R = MAX - y_index
		for (x = 0; x < block_count; x++){
			// inv( x_index ^ y_R )
			matrix[block_count * y + x] = gf8_reciprocal(gf_table, x ^ y_R);
		}

		// No need to set values for recovery blocks,
		// because they will be put in positions of lost blocks.
	}

	if (par3_ctx->noise_level >= 2){
		printf("\n generator matrix (%d * %d):\n", block_count, lost_count);
		for (y = 0; y < lost_count; y++){
			printf("lost%3d <- recv%3d =", lost_id[y], recv_id[y]);
			for (x = 0; x < block_count; x++){
				printf(" %2x", matrix[block_count * y + x]);
			}
			printf("\n");
		}
	}

	// Gaussian elimination
	for (y = 0; y < lost_count; y++){
		// Let pivot value to be 1.
		pivot = lost_id[y];
		factor = matrix[block_count * y + pivot];
		if (factor == 0){
			printf("Failed to invert matrix\n");
			return RET_LOGIC_ERROR;
		}
		factor = gf8_reciprocal(gf_table, factor);
		gf8_region_multiply(gf_table, matrix + block_count * y, factor, block_count, NULL, 0);

		// Erase values of same pivot on other rows.
		for (y2 = 0; y2 < lost_count; y2++){
			if (y2 == y)
				continue;

			factor2 = matrix[block_count * y2 + pivot];
			gf8_region_multiply(gf_table, matrix + block_count * y, factor2, block_count, matrix + block_count * y2, 1);

			// After eliminate the pivot value, store "factor * factor2" value on the pivot.
			matrix[block_count * y2 + pivot] = gf8_multiply(gf_table, factor, factor2);
		}

		// After eliminate the pivot columun, store "factor" value on the pivot.
		matrix[block_count * y + pivot] = factor;
	}

	if (par3_ctx->noise_level >= 2){
		printf("\n recovery matrix (%d * %d):\n", block_count, lost_count);
		for (y = 0; y < lost_count; y++){
			printf("recv%3d -> lost%3d =", recv_id[y], lost_id[y]);
			for (x = 0; x < block_count; x++){
				printf(" %2x", matrix[block_count * y + x]);
			}
			printf("\n");
		}
	}

	return 0;
}

