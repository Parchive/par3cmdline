// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "galois.h"


// This will allocate recovery blocks on memory.
int create_recovery_block(PAR3_CTX *par3_ctx)
{
	uint64_t block_size, block_count, recovery_block_count;

	if (par3_ctx->recovery_block_count == 0)
		return 0;

	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	recovery_block_count = par3_ctx->recovery_block_count;

	if (par3_ctx->galois_poly == 0x1100B){	// 16-bit Galois Field (0x1100B).


	} else if (par3_ctx->galois_poly == 0x11D){	// 8-bit Galois Field (0x11D).
		par3_ctx->galois_table = gf8_create_table(par3_ctx->galois_poly);




	}
	if (par3_ctx->galois_table == NULL){
		printf("Failed to create tables for Galois Field (0x%X)\n", par3_ctx->galois_poly);
		return RET_MEMORY_ERROR;
	}

/*
	// Try to allocate all recovery blocks on memory
	par3_ctx->recovery_data = malloc(block_size * recovery_block_count);
	if (par3_ctx->recovery_data == NULL){
		perror("Failed to allocate memory for recovery data");
		return RET_MEMORY_ERROR;
	}
*/


/*
{	// for debug
	int x, y, z, w;
	unsigned char buf1[256], buf2[256], buf3[256];

	for (y = 1; y < 256; y++){
		// z = 1 / y
		z = gf8_divide(par3_ctx->galois_table, 1, y);
		w = gf8_reciprocal(par3_ctx->galois_table, y);
		if (z != w){
			printf("Error: y = %d, 1/y = %d, %d\n", y, z, w);
			break;
		}

		for (x = 0; x < 256; x++){
			// z = x * y
			z = gf8_multiply(par3_ctx->galois_table, x, y);
			w = gf8_fast_multiply(par3_ctx->galois_table, x, y);
			if (z != w){
				printf("Error: x = %d, y = %d, x*y = %d, %d\n", x, y, z, w);
				break;
			} else {
				w = gf8_divide(par3_ctx->galois_table, z, y);
				if (w != x){
					printf("Error: x = %d, y = %d, x*y = %d, x*y/y = %d\n", x, y, z, w);
					x = y = 256;
					break;
				}
				if (x > 0){
					w = gf8_divide(par3_ctx->galois_table, z, x);
					if (w != y){
						printf("Error: x = %d, y = %d, x*y = %d, x*y/x = %d\n", x, y, z, w);
						x = y = 256;
						break;
					}
				}
			}
		}
	}

	for (x = 0; x < 256; x++){
		buf1[x] = x;
		buf2[x] = 255;
		buf3[x] = gf8_multiply(par3_ctx->galois_table, x, 255) ^ 255;
	}
	gf8_region_multiply(par3_ctx->galois_table, buf1, 255, 256, buf2);
	if (memcmp(buf2, buf3, 256) != 0){
		printf("Error: gf8_region_multiply\n");
	}

	printf("\n test OK !\n");
}
*/


	return 0;
}

