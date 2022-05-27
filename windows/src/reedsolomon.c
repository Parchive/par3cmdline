
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "galois.h"
#include "hash.h"
#include "reedsolomon.h"


// Create all recovery blocks from one input block.
void rs_create_one_all(PAR3_CTX *par3_ctx, int x_index)
{
	void *gf_table;
	uint8_t *work_buf, *buf_p;
	uint8_t gf_size;
	int first_num, element;
	int y_index, y_R;
	int recovery_block_count;
	size_t region_size;

	recovery_block_count = (int)(par3_ctx->recovery_block_count);
	first_num = (int)(par3_ctx->first_recovery_block);
	gf_size = par3_ctx->gf_size;
	gf_table = par3_ctx->galois_table;
	work_buf = par3_ctx->work_buf;
	buf_p = par3_ctx->block_data;

	// For every recovery block
	region_size = (par3_ctx->block_size + 4 + 3) & ~3;
	for (y_index = 0; y_index < recovery_block_count; y_index++){
		// Calculate Matrix elements
		if (par3_ctx->gf_size == 2){	// 16-bit Galois Field
			y_R = 65535 - (y_index + first_num);
			element = gf16_reciprocal(gf_table, x_index ^ y_R);	// inv( x_index ^ y_R )

			// If x_index == 0, just put values.
			// If x_index > 0, add values on previous values.
			gf16_region_multiply(gf_table, work_buf, element, region_size, buf_p, x_index);

		} else {	// 8-bit Galois Field
			y_R = 255 - (y_index + first_num);
			element = gf8_reciprocal(gf_table, x_index ^ y_R);	// inv( x_index ^ y_R )

			// If x_index == 0, just put values.
			// If x_index > 0, add values on previous values.
			gf8_region_multiply(gf_table, work_buf, element, region_size, buf_p, x_index);
		}
		//printf("x = %d, R = %d, y_R = %d, element = %d\n", x_index, y_index + first_num, y_R, element);

		buf_p += region_size;
	}
}

// Construct matrix for Cauchy Reed-Solomon, and solve linear equation.
int rs_compute_matrix(PAR3_CTX *par3_ctx, uint64_t lost_count)
{
	uint8_t *packet_checksum;
	int ret;
	int *lost_id, *recv_id;
	size_t alloc_size, region_size;
	uint64_t count, index, id;
	PAR3_BLOCK_CTX *block_list;
	PAR3_PKT_CTX *packet_list;

	if (par3_ctx->gf_size == 2){	// 16-bit Galois Field
		par3_ctx->galois_table = gf16_create_table(par3_ctx->galois_poly);

	} else if (par3_ctx->gf_size == 1){	// 8-bit Galois Field
		par3_ctx->galois_table = gf8_create_table(par3_ctx->galois_poly);

	} else {
		printf("Galois Field (0x%X) isn't supported.\n", par3_ctx->galois_poly);
		return RET_LOGIC_ERROR;
	}
	if (par3_ctx->galois_table == NULL){
		printf("Failed to create tables for Galois Field (0x%X)\n", par3_ctx->galois_poly);
		return RET_MEMORY_ERROR;
	}

	// Only when it uses Reed-Solomon Erasure Codes.
	if ((par3_ctx->ecc_method & 1) == 0)
		return 0;

	// Make list of index (lost input blocks and using recovery blocks)
	lost_id = (int *) malloc(sizeof(int) * lost_count * 2);
	if (lost_id == NULL){
		printf("Failed to make list for using blocks\n");
		return RET_MEMORY_ERROR;
	}
	recv_id = lost_id + lost_count;
	par3_ctx->id_list = lost_id;

	// Get checksum of using Matrix Packet
	packet_checksum = par3_ctx->matrix_packet + par3_ctx->matrix_packet_offset + 8;

	// Set index of using recovery blocks
	packet_list = par3_ctx->rec_data_packet_list;
	count = par3_ctx->rec_data_packet_count;
	id = 0;
	for (index = 0; index < count; index++){
		// Search only Recovery Data Packets belong to using Matrix Packet
		if (memcmp(packet_list[index].matrix, packet_checksum, 16) == 0){
			recv_id[id] = (int)(packet_list[index].index);
			//printf("recv_id[%I64u] = %d\n", id, recv_id[id]);
			id++;

			// If there are more blocks than required, just ignore them.
			// Cauchy Matrix should be invertible always.
			// Or, is it safe to keep more for full rank ?
			if (id >= lost_count)
				break;
		}
	}

	// Set index of lost input blocks
	block_list = par3_ctx->block_list;
	count = par3_ctx->block_count;
	id = 0;
	for (index = 0; index < count; index++){
		if ((block_list[index].state & (4 | 16)) == 0){
			if (id >= lost_count){
				printf("Number of lost input blocks is wrong.\n");
				return RET_LOGIC_ERROR;
			}

			lost_id[id] = (int)index;
			//printf("lost_id[%I64u] = %d\n", id, lost_id[id]);
			id++;
		}
	}

	// Make matrix
	if (par3_ctx->gf_size == 2){	// 16-bit Reed-Solomon Codes
		// Either functions should work.
		// As blocks are more, Gaussian elimination become too slow.
		//ret = rs16_gaussian_elimination(par3_ctx, (int)lost_count);
		ret = rs16_invert_matrix_cauchy(par3_ctx, (int)lost_count);
		if (ret != 0)
			return ret;

	} else if (par3_ctx->gf_size == 1){	// 8-bit Reed-Solomon Codes
		// Either functions should work.
		// Gaussian elimination is enough fast for a few blocks.
		ret = rs8_gaussian_elimination(par3_ctx, (int)lost_count);
		//ret = rs8_invert_matrix_cauchy(par3_ctx, (int)lost_count);
		if (ret != 0)
			return ret;
	}

	// Set memory alignment of block data to be 4.
	// Increase at least 1 byte as checksum.
	region_size = (par3_ctx->block_size + 4 + 3) & ~3;
	if (par3_ctx->noise_level >= 2){
		printf("\nAligned size of block data = %zu\n", region_size);
	}

	// Limited memory usage
	alloc_size = region_size * lost_count;
	if ( (par3_ctx->memory_limit > 0) && (alloc_size > par3_ctx->memory_limit) )
		return 0;

	// Allocate memory to keep lost blocks
	par3_ctx->block_data = malloc(alloc_size);
	if (par3_ctx->block_data == NULL){
		// When it cannot allocate memory, it will retry later.
		par3_ctx->ecc_method &= ~0x1000;
	} else {
		par3_ctx->ecc_method |= 0x1000;	// Keep all lost blocks on memory
	}

	return 0;
}

