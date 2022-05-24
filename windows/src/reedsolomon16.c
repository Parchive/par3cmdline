
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


// Gaussian elimination for Cauchy Reed-Solomon
int rs16_gaussian_elimination(PAR3_CTX *par3_ctx, int lost_count)
{
	uint16_t *matrix;
	int x, y, y_R, y2;
	int *gf_table, *lost_id, *recv_id;
	int block_count, total_count, matrix_width;
	int pivot, factor, factor2;
	int progress_old, progress_now;
	time_t time_old, time_now;
	clock_t clock_now;

	block_count = (int)(par3_ctx->block_count);
	gf_table = par3_ctx->galois_table;
	lost_id = par3_ctx->id_list;
	recv_id = lost_id + lost_count;

	total_count = block_count + lost_count;

	// Matrix rows are aligned to 8 bytes.
	matrix_width = (total_count + 3) & ~3;

	// Allocate matrix on memory
	matrix = malloc(sizeof(uint16_t) * matrix_width * lost_count);
	if (matrix == NULL){
		printf("Failed to allocate memory for matrix\n");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->matrix = matrix;

	// Set matrix elements
	for (y = 0; y < lost_count; y++){	// per each recovery block
		// Left side
		y_R = 65535 - recv_id[y];	// y_R = MAX - y_index
		for (x = 0; x < block_count; x++){
			// inv( x_index ^ y_R )
			matrix[matrix_width * y + x] = gf16_reciprocal(gf_table, x ^ y_R);
		}

		// Right side
		for (x = 0; x < lost_count; x++){
			if (x == y){
				factor = 1;
			} else {
				factor = 0;
			}
			matrix[matrix_width * y + block_count + x] = factor;
		}
	}


	if (par3_ctx->noise_level >= 2){
		printf("\n generator matrix (%d * %d):\n", total_count, lost_count);
		for (y = 0; y < lost_count; y++){
			printf("lost%5d <- recv%5d =", lost_id[y], recv_id[y]);
			for (x = 0; x < block_count; x++){
				printf(" %4x", matrix[matrix_width * y + x]);
			}
			printf(" |");
			for (x = block_count; x < total_count; x++){
				printf(" %4x", matrix[matrix_width * y + x]);
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
		factor = matrix[matrix_width * y + pivot];
		if (factor == 0){
			printf("Failed to invert matrix\n");
			return RET_LOGIC_ERROR;
		}
		factor = gf16_reciprocal(gf_table, factor);
		gf16_region_multiply(gf_table, (uint8_t *)(matrix + matrix_width * y), factor, total_count * 2, NULL, 0);

		// Erase values of same pivot on other rows.
		for (y2 = 0; y2 < lost_count; y2++){
			if (y2 == y)
				continue;

			factor2 = matrix[matrix_width * y2 + pivot];
			gf16_region_multiply(gf_table, (uint8_t *)(matrix + matrix_width * y), factor2, total_count * 2, (uint8_t *)(matrix + matrix_width * y2), 1);
		}

		// Print progress percent
		if (par3_ctx->noise_level >= 0){
			time_now = time(NULL);
			if (time_now != time_old){
				time_old = time_now;
				// Complexity is "lost_count * lost_count * total_count".
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
		printf("\n recovery matrix (%d * %d):\n", total_count, lost_count);
		for (y = 0; y < lost_count; y++){
			printf("recv%5d -> lost%5d =", recv_id[y], lost_id[y]);
			for (x = 0; x < block_count; x++){
				printf(" %4x", matrix[matrix_width * y + x]);
			}
			printf(" |");
			for (x = block_count; x < total_count; x++){
				printf(" %4x", matrix[matrix_width * y + x]);
			}
			printf("\n");
		}
	}

	return 0;
}

