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

	if (lost_count == 0)
		return 0;

	block_count = (int)(par3_ctx->block_count);
	gf_table = par3_ctx->galois_table;
	recv_id = par3_ctx->recv_id_list;
	lost_id = recv_id + lost_count;

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

	if (par3_ctx->noise_level >= 3){
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

	if (par3_ctx->noise_level >= 3){
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


/*

Fast inversion for Cauchy matrix
This method is based on sample code of persicum's RSC32.

The inverting theory may be described in these pages;

Cauchy matrix
https://en.wikipedia.org/wiki/Cauchy_matrix

Inverse of Cauchy Matrix
https://proofwiki.org/wiki/Inverse_of_Cauchy_Matrix

*/
int rs16_invert_matrix_cauchy(PAR3_CTX *par3_ctx, int lost_count)
{
	uint16_t *gf_table, *matrix;
	int *x, *y, *a, *b, *c, *d;
	int i, j, k;
	int *lost_id, *recv_id;
	int block_count;
	int progress_old, progress_now;
	time_t time_old, time_now;
	clock_t clock_now;

	if (lost_count == 0)
		return 0;

	block_count = (int)(par3_ctx->block_count);
	gf_table = par3_ctx->galois_table;
	recv_id = par3_ctx->recv_id_list;
	lost_id = recv_id + lost_count;

	// Allocate matrix on memory
	matrix = malloc(sizeof(uint16_t) * block_count * lost_count);
	if (matrix == NULL){
		printf("Failed to allocate memory for matrix\n");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->matrix = matrix;

	// Allocate working buffer on memory
	a = calloc(block_count * 6, sizeof(int));
	if (a == NULL){
		printf("Failed to allocate memory for inversion\n");
		return RET_MEMORY_ERROR;
	}
	b = a + block_count;
	c = b + block_count;
	d = c + block_count;
	x = d + block_count;
	y = x + block_count;

	if (par3_ctx->noise_level >= 0){
		printf("\nComputing Reed Solomon matrix:\n");
		progress_old = 0;
		time_old = time(NULL);
		clock_now = clock();
	}

	// Set index of lost input blocks
	for (i = 0; i < lost_count; i++){
		y[i] = lost_id[i];
	}
	// Set index of existing input blocks after
	k = 0;
	for (j = 0; j < block_count; j++){
		if (k < lost_count && j == lost_id[k]){
			k++;
			continue;
		}
		y[i] = j;
		i++;
	}

	// Set index of using recovery blocks
	for (i = 0; i < lost_count; i++){
		x[i] = 65535 - recv_id[i];	// y_R = MAX - y_index
	}
	// Set index of existing input blocks after
	for (; i < block_count; i++){
		x[i] = y[i];
	}

	for (i = 0; i < block_count; i++){
		a[i] = 1;
		b[i] = 1;
		c[i] = 1;
		d[i] = 1;

		for (j = 0; j < lost_count; j++){
			if (i != j){
				a[i] = gf16_multiply(gf_table, a[i], x[i] ^ x[j]);
				b[i] = gf16_multiply(gf_table, b[i], y[i] ^ y[j]);
			}

			c[i] = gf16_multiply(gf_table, c[i], x[i] ^ y[j]);
			d[i] = gf16_multiply(gf_table, d[i], y[i] ^ x[j]);
		}

		// Print progress percent
		if (par3_ctx->noise_level >= 0){
			time_now = time(NULL);
			if (time_now != time_old){
				time_old = time_now;
				// Complexity is "lost_count * block_count * 2".
				// Because lost_count is 16-bit value, "int" (32-bit signed integer) is enough.
				progress_now = (i * 1000) / (block_count + lost_count);
				if (progress_now != progress_old){
					progress_old = progress_now;
					printf("%d.%d%%\r", progress_now / 10, progress_now % 10);	// 0.0% ~ 100.0%
				}
			}
		}
	}

/*
	if (par3_ctx->noise_level >= 3){
		printf("\n fast inversion (%d * 6):\n", block_count);
		printf("y =");
		for (i = 0; i < block_count; i++){
			printf(" %4x", y[i]);
		}
		printf("\n");
		printf("x =");
		for (i = 0; i < block_count; i++){
			printf(" %4x", x[i]);
		}
		printf("\n");
		printf("a =");
		for (i = 0; i < block_count; i++){
			printf(" %4x", a[i]);
		}
		printf("\n");
		printf("b =");
		for (i = 0; i < block_count; i++){
			printf(" %4x", b[i]);
		}
		printf("\n");
		printf("c =");
		for (i = 0; i < block_count; i++){
			printf(" %4x", c[i]);
		}
		printf("\n");
		printf("d =");
		for (i = 0; i < block_count; i++){
			printf(" %4x", d[i]);
		}
		printf("\n");
	}
*/

	for (i = 0; i < lost_count; i++){
		for (j = 0; j < block_count; j++){
			k = gf16_multiply(gf_table, a[j], b[i]);
			k = gf16_reciprocal(gf_table, gf16_multiply(gf_table, k, x[j] ^ y[i]));
			k = gf16_multiply(gf_table, gf16_multiply(gf_table, c[j], d[i]), k);
			matrix[ block_count * i + y[j] ] = k;
		}

		// Print progress percent
		if (par3_ctx->noise_level >= 0){
			time_now = time(NULL);
			if (time_now != time_old){
				time_old = time_now;
				// Complexity is "lost_count * block_count * 2".
				// Because lost_count is 16-bit value, "int" (32-bit signed integer) is enough.
				progress_now = ((block_count + i) * 1000) / (block_count + lost_count);
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

	if (par3_ctx->noise_level >= 3){
		printf("\n recovery matrix (%d * %d):\n", block_count, lost_count);
		for (i = 0; i < lost_count; i++){
			printf("recv%5d -> lost%5d =", recv_id[i], lost_id[i]);
			for (j = 0; j < block_count; j++){
				printf(" %4x", matrix[block_count * i + j]);
			}
			printf("\n");
		}
	}

	// Deallocate working buffer
	free(a);

	return 0;
}

