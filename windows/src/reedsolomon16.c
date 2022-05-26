
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libpar3.h"
#include "galois.h"


// Gaussian elimination of matrix for Cauchy Reed-Solomon
int rs16_gaussian_elimination(PAR3_CTX *par3_ctx, int lost_count)
{
	uint16_t *gf_table, *matrix;
	int x, y, y_R, y2;
	int *lost_id, *recv_id;
	int block_count;
	int pivot, factor, factor2;
	int progress_old, progress_now;
	time_t time_old, time_now;
	clock_t clock_now;

	block_count = (int)(par3_ctx->block_count);
	gf_table = par3_ctx->galois_table;
	lost_id = par3_ctx->id_list;
	recv_id = lost_id + lost_count;

	// Allocate matrix on memory
	matrix = malloc(sizeof(uint16_t) * block_count * lost_count);
	if (matrix == NULL){
		printf("Failed to allocate memory for matrix\n");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->matrix = matrix;

	// Set matrix elements
	for (y = 0; y < lost_count; y++){	// per each recovery block
		// These are elements of generator matrix.
		y_R = 65535 - recv_id[y];	// y_R = MAX - y_index
		for (x = 0; x < block_count; x++){
			// inv( x_index ^ y_R )
			matrix[block_count * y + x] = gf16_reciprocal(gf_table, x ^ y_R);
		}

		// No need to set values for recovery blocks,
		// because they will be put in positions of lost blocks.
	}

	if (par3_ctx->noise_level >= 2){
		printf("\n generator matrix (%d * %d):\n", block_count, lost_count);
		for (y = 0; y < lost_count; y++){
			printf("lost%5d <- recv%5d =", lost_id[y], recv_id[y]);
			for (x = 0; x < block_count; x++){
				printf(" %4x", matrix[block_count * y + x]);
			}
			printf("\n");
		}
	}

	// Gaussian elimination
	if (par3_ctx->noise_level >= 0){
		printf("\nComputing Reed Solomon matrix:\n");
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}
	for (y = 0; y < lost_count; y++){
		// Let pivot value to be 1.
		pivot = lost_id[y];
		factor = matrix[block_count * y + pivot];
		if (factor == 0){
			printf("Failed to invert matrix\n");
			return RET_LOGIC_ERROR;
		}
		factor = gf16_reciprocal(gf_table, factor);
		gf16_region_multiply(gf_table, (uint8_t *)(matrix + block_count * y), factor, block_count * 2, NULL, 0);

		// Erase values of same pivot on other rows.
		for (y2 = 0; y2 < lost_count; y2++){
			if (y2 == y)
				continue;

			factor2 = matrix[block_count * y2 + pivot];
			gf16_region_multiply(gf_table, (uint8_t *)(matrix + block_count * y), factor2, block_count * 2, (uint8_t *)(matrix + block_count * y2), 1);

			// After eliminate the pivot value, store "factor * factor2" value on the pivot.
			matrix[block_count * y2 + pivot] = gf16_multiply(gf_table, factor, factor2);
		}

		// After eliminate the pivot columun, store "factor" value on the pivot.
		matrix[block_count * y + pivot] = factor;

		// Print progress percent
		if (par3_ctx->noise_level >= 0){
			time_now = time(NULL);
			if (time_now != time_old){
				time_old = time_now;
				// Complexity is "lost_count * lost_count * block_count".
				// Because lost_count is 16-bit value, "int" (32-bit signed integer) is enough.
				progress_now = (y * 1000) / lost_count;
				if (progress_now != progress_old){
					progress_old = progress_now;
					printf("%d.%d%%\r", progress_now / 10, progress_now % 10);	// 0.0% ~ 100.0%
				}
			}
		}
	}
	if (par3_ctx->noise_level >= 0){
		clock_now = clock() - clock_now;
		printf("done in %.1f seconds.\n", (double)clock_now / CLOCKS_PER_SEC);
	}

	if (par3_ctx->noise_level >= 2){
		printf("\n recovery matrix (%d * %d):\n", block_count, lost_count);
		for (y = 0; y < lost_count; y++){
			printf("recv%5d -> lost%5d =", recv_id[y], lost_id[y]);
			for (x = 0; x < block_count; x++){
				printf(" %4x", matrix[block_count * y + x]);
			}
			printf("\n");
		}
	}

	return 0;
}

