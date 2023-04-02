
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

	if (lost_count == 0)
		return 0;

	block_count = (int)(par3_ctx->block_count);
	gf_table = par3_ctx->galois_table;
	recv_id = par3_ctx->recv_id_list;
	lost_id = recv_id + lost_count;

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

	if (par3_ctx->noise_level >= 3){
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

	if (par3_ctx->noise_level >= 3){
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


/*

Fast inversion for Cauchy matrix
This method is based on sample code of persicum's RSC32.

The inverting theory may be described in these pages;

Cauchy matrix
https://en.wikipedia.org/wiki/Cauchy_matrix

Inverse of Cauchy Matrix
https://proofwiki.org/wiki/Inverse_of_Cauchy_Matrix

*/
int rs8_invert_matrix_cauchy(PAR3_CTX *par3_ctx, int lost_count)
{
	uint8_t *gf_table, *matrix;
	int *x, *y, *a, *b, *c, *d;
	int i, j, k;
	int *lost_id, *recv_id;
	int block_count;

	if (lost_count == 0)
		return 0;

	block_count = (int)(par3_ctx->block_count);
	gf_table = par3_ctx->galois_table;
	recv_id = par3_ctx->recv_id_list;
	lost_id = recv_id + lost_count;

	// Allocate matrix on memory
	matrix = malloc(block_count * lost_count);
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

	// Set index of lost input blocks
	for (i = 0; i < lost_count; i++){
		y[i] = lost_id[i];
	}
	// Set index of existing input blocks after
	k = 0;
	for (j = 0; j < block_count; j++){
		if (j == lost_id[k]){
			k++;
			continue;
		}
		y[i] = j;
		i++;
	}

	// Set index of using recovery blocks
	for (i = 0; i < lost_count; i++){
		x[i] = 255 - recv_id[i];	// y_R = MAX - y_index
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
				a[i] = gf8_multiply(gf_table, a[i], x[i] ^ x[j]);
				b[i] = gf8_multiply(gf_table, b[i], y[i] ^ y[j]);
			}

			c[i] = gf8_multiply(gf_table, c[i], x[i] ^ y[j]);
			d[i] = gf8_multiply(gf_table, d[i], y[i] ^ x[j]);
		}
	}

/*
	if (par3_ctx->noise_level >= 3){
		printf("\n fast inversion (%d * 6):\n", block_count);
		printf("y =");
		for (i = 0; i < block_count; i++){
			printf(" %2x", y[i]);
		}
		printf("\n");
		printf("x =");
		for (i = 0; i < block_count; i++){
			printf(" %2x", x[i]);
		}
		printf("\n");
		printf("a =");
		for (i = 0; i < block_count; i++){
			printf(" %2x", a[i]);
		}
		printf("\n");
		printf("b =");
		for (i = 0; i < block_count; i++){
			printf(" %2x", b[i]);
		}
		printf("\n");
		printf("c =");
		for (i = 0; i < block_count; i++){
			printf(" %2x", c[i]);
		}
		printf("\n");
		printf("d =");
		for (i = 0; i < block_count; i++){
			printf(" %2x", d[i]);
		}
		printf("\n");
	}
*/

	for (i = 0; i < lost_count; i++){
		for (j = 0; j < block_count; j++){
			k = gf8_multiply(gf_table, a[j], b[i]);
			k = gf8_reciprocal(gf_table, gf8_multiply(gf_table, k, x[j] ^ y[i]));
			k = gf8_multiply(gf_table, gf8_multiply(gf_table, c[j], d[i]), k);
			matrix[ block_count * i + y[j] ] = k;
		}
	}

	if (par3_ctx->noise_level >= 3){
		printf("\n recovery matrix (%d * %d):\n", block_count, lost_count);
		for (i = 0; i < lost_count; i++){
			printf("recv%3d -> lost%3d =", recv_id[i], lost_id[i]);
			for (j = 0; j < block_count; j++){
				printf(" %2x", matrix[block_count * i + j]);
			}
			printf("\n");
		}
	}

	// Deallocate working buffer
	free(a);

	return 0;
}

