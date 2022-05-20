// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"


// Data Packets substitute for lost input blocks.
int substitute_input_block(PAR3_CTX *par3_ctx)
{
	int flag_show = 0, flag_substitute;
	int64_t slice_index;
	uint64_t item_index, packet_count;
	uint64_t block_size, block_count, block_index;
	PAR3_PKT_CTX *packet_list;
	PAR3_BLOCK_CTX *block_list;
	PAR3_SLICE_CTX *slice_list;

	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;
	packet_list = par3_ctx->data_packet_list;
	packet_count = par3_ctx->data_packet_count;

	if ( (block_list == NULL) || (packet_list == NULL) )
		return 0;

	for (item_index = 0; item_index < packet_count; item_index++){
		block_index = packet_list[item_index].index;
		if (block_index >= block_count){
			printf("Data Packet for block[%I64u] is wrong.\n", block_index);
			return RET_LOGIC_ERROR;
		}

		// Update all slices in the block
		flag_substitute = 0;
		slice_index = block_list[block_index].slice;
		while (slice_index != -1){
			if (slice_list[slice_index].find_name == NULL){
				flag_substitute++;
				slice_list[slice_index].find_name = packet_list[item_index].name;
				if (slice_list[slice_index].size == block_size){
					slice_list[slice_index].find_offset = packet_list[item_index].offset + 56;
				} else {
					slice_list[slice_index].find_offset = packet_list[item_index].offset + 56 + slice_list[slice_index].tail_offset;
				}
			}
			slice_index = slice_list[slice_index].next;
		}

		// Update found state
		if (block_list[block_index].state & 1){	// Block of full size slice
			block_list[block_index].state |= 4;
		} else if (block_list[block_index].state & 2){	// Block of tail slices
			block_list[block_index].state |= 8 | 16;
		}
		if (flag_substitute > 0){
			if (par3_ctx->noise_level >= 2){
				if (flag_show == 0){
					flag_show++;
					printf("\nSubstituting for lost blocks:\n\n");
				}
				printf("Map block[%2I64d] to Data Packet.\n", block_index);
			}
		}
	}

	return 0;
}

// Find identical input blocks
int find_identical_block(PAR3_CTX *par3_ctx)
{
	int flag_show = 0;
	int64_t slice_index, find_index;
	int64_t slice_index_i, slice_index_j;
	uint64_t i, j, count;
	uint64_t block_index_i, block_index_j;
	PAR3_CMP_CTX *cmp_list;
	PAR3_BLOCK_CTX *block_list;
	PAR3_SLICE_CTX *slice_list;
	PAR3_CHUNK_CTX *chunk_list;

/*
	// for debug
	for (i = 0; i < par3_ctx->crc_count; i++){
		printf("crc_list[%2I64u] = 0x%016I64x , block = %I64u\n", i, par3_ctx->crc_list[i].crc, par3_ctx->crc_list[i].index);
	}
	for (i = 0; i < par3_ctx->tail_count; i++){
		printf("tail_list[%2I64u] = 0x%016I64x , slice = %I64u\n", i, par3_ctx->tail_list[i].crc, par3_ctx->tail_list[i].index);
	}
*/

	// Compare full size blocks.
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;
	cmp_list = par3_ctx->crc_list;
	count = par3_ctx->crc_count;
	for (i = 0; i < count; i++){
		for (j = i + 1; j < count; j++){
			if (cmp_list[i].crc == cmp_list[j].crc){
				// When CRC-64 of these blocks are same, compare hash values next.
				block_index_i = cmp_list[i].index;
				block_index_j = cmp_list[j].index;
				if (memcmp(block_list[block_index_i].hash, block_list[block_index_j].hash, 16) == 0){
					//printf("block[%I64u] and [%I64u] are same.\n", block_index_i, block_index_j);
					if (block_list[block_index_i].state & 4){	// block[i] is found.
						if ((block_list[block_index_j].state & 4) == 0){	// block[j] isn't found.
							if (par3_ctx->noise_level >= 2){
								if (flag_show == 0){
									flag_show++;
									printf("\nComparing lost slices to found slices:\n\n");
								}
								printf("Map block[%2I64u] to identical block[%2I64u].\n", block_index_j, block_index_i);
							}
							slice_index = block_list[block_index_j].slice;
							find_index = block_list[block_index_i].slice;
							// Search valid slice for this found block.
							while ( (find_index != -1) && (slice_list[find_index].find_name == NULL) ){
								find_index = slice_list[find_index].next;
							}
							if (find_index == -1){
								// When there is no valid slice.
								printf("Mapping information for block[%I64u] is wrong.\n", block_index_i);
								return RET_LOGIC_ERROR;
							}
							// Copy reading source to another.
							slice_list[slice_index].find_name = slice_list[find_index].find_name;
							slice_list[slice_index].find_offset = slice_list[find_index].find_offset;
							block_list[block_index_j].state |= 4;
						}
					} else if (block_list[block_index_j].state & 4){	// block[i] isn't found, and block[j] is found.
						if (par3_ctx->noise_level >= 2){
							if (flag_show == 0){
								flag_show++;
								printf("\nComparing lost slices to found slices:\n\n");
							}
							printf("Map block[%2I64u] to identical block[%2I64u].\n", block_index_i, block_index_j);
						}
						slice_index = block_list[block_index_i].slice;
						find_index = block_list[block_index_j].slice;
						// Search valid slice for this found block.
						while ( (find_index != -1) && (slice_list[find_index].find_name == NULL) ){
							find_index = slice_list[find_index].next;
						}
						if (find_index == -1){
							// When there is no valid slice.
							printf("Mapping information for block[%I64u] is wrong.\n", block_index_j);
							return RET_LOGIC_ERROR;
						}
						// Copy reading source to another.
						slice_list[slice_index].find_name = slice_list[find_index].find_name;
						slice_list[slice_index].find_offset = slice_list[find_index].find_offset;
						block_list[block_index_i].state |= 4;
					}
				}

			} else {	// Because CRC list was sorted, no need to compare after different CRC.
				break;
			}
		}

		// When there are multiple slices for a block, map all slices.
		block_index_i = cmp_list[i].index;
		if (block_list[block_index_i].state & 4){	// block[i] has a valid slice.
			slice_index = block_list[block_index_i].slice;
			// Find valid slice.
			find_index = slice_index;
			while ( (find_index != -1) && (slice_list[find_index].find_name == NULL) ){
				find_index = slice_list[find_index].next;
			}
			if (find_index == -1){
				// When there is no valid slice.
				printf("Mapping information for block[%I64u] is wrong.\n", block_index_i);
				return RET_LOGIC_ERROR;
			}
			// Map other slices.
			do {
				if (slice_list[slice_index].find_name == NULL){
					if (par3_ctx->noise_level >= 2){
						if (flag_show == 0){
							flag_show++;
							printf("\nComparing lost slices to found slices:\n\n");
						}
						printf("Map slice[%2I64d] to identical slice[%2I64d] in block[%2I64u].\n",
								slice_index, find_index, block_index_i);
					}
					slice_list[slice_index].find_name = slice_list[find_index].find_name;
					slice_list[slice_index].find_offset = slice_list[find_index].find_offset;
				}
				slice_index = slice_list[slice_index].next;
			} while (slice_index != -1);
		}
	}

	// Compare chunk tail slices.
	chunk_list = par3_ctx->chunk_list;
	cmp_list = par3_ctx->tail_list;
	count = par3_ctx->tail_count;
	for (i = 0; i < count; i++){
		for (j = i + 1; j < count; j++){
			if (cmp_list[i].crc == cmp_list[j].crc){
				// When CRC-64 of these slices are same, compare size and hash values next.
				slice_index_i = cmp_list[i].index;
				slice_index_j = cmp_list[j].index;
				if (slice_list[slice_index_i].size == slice_list[slice_index_j].size){
					if (memcmp(chunk_list[slice_list[slice_index_i].chunk].tail_hash, chunk_list[slice_list[slice_index_j].chunk].tail_hash, 16) == 0){
						//printf("slice[%I64u] and [%I64u] are same.\n", slice_index_i, slice_index_j);
						if (slice_list[slice_index_i].find_name != NULL){	// slice[i] is found.
							if (slice_list[slice_index_j].find_name == NULL){	// slice[j] isn't found.
								if (par3_ctx->noise_level >= 2){
									if (flag_show == 0){
										flag_show++;
										printf("\nComparing lost slices to found slices:\n\n");
									}
									printf("Map slice[%2I64u] to identical slice[%2I64u].\n", slice_index_j, slice_index_i);
								}
								// Copy reading source to another.
								block_index_j = slice_list[slice_index_j].block;
								slice_list[slice_index_j].find_name = slice_list[slice_index_i].find_name;
								slice_list[slice_index_j].find_offset = slice_list[slice_index_i].find_offset;
								block_list[block_index_j].state |= 8;
							}
						} else if (slice_list[slice_index_j].find_name != NULL){	// slice[i] isn't found, and slice[j] is found.
							if (par3_ctx->noise_level >= 2){
								if (flag_show == 0){
									flag_show++;
									printf("\nComparing lost slices to found slices:\n\n");
								}
								printf("Map slice[%2I64d] to identical slice[%2I64d].\n", slice_index_i, slice_index_j);
							}
							// Copy reading source to another.
							block_index_i = slice_list[slice_index_i].block;
							slice_list[slice_index_i].find_name = slice_list[slice_index_j].find_name;
							slice_list[slice_index_i].find_offset = slice_list[slice_index_j].find_offset;
							block_list[block_index_i].state |= 8;
						}
					}
				}

			} else {	// Because CRC list was sorted, no need to compare after different CRC.
				break;
			}
		}
	}

	return 0;
}

// Aggregate verified result of available input blocks
uint64_t aggregate_input_block(PAR3_CTX *par3_ctx)
{
	int64_t slice_index;
	uint64_t block_count, block_available, block_index;
	uint64_t total_size, available_size, skip_count, old_count;
	PAR3_BLOCK_CTX *block_list;
	PAR3_SLICE_CTX *slice_list;

	block_count = par3_ctx->block_count;
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;

	block_available = 0;
	for (block_index = 0; block_index < block_count; block_index++){
		if (block_list[block_index].state & (4 | 16)){
			// When a block has a full slice, the whole block data is available.
			block_available++;

		} else if (block_list[block_index].state & 8){
			// When a block has a tail slice, I need to check which data is available.
			skip_count = old_count = 0;
			available_size = 0;
			total_size = block_list[block_index].size;	// total data size of chunk tails in this block
			slice_index = block_list[block_index].slice;	// index of the first slice
			while (slice_index != -1){
				if (slice_list[slice_index].find_name != NULL){
					if (slice_list[slice_index].tail_offset > available_size){
						skip_count++;
						//printf("block[%I64u]: skip_count = %I64u\n", block_index, skip_count);
					} else if (slice_list[slice_index].tail_offset + slice_list[slice_index].size >= available_size){
						available_size = slice_list[slice_index].tail_offset + slice_list[slice_index].size;
						//printf("block[%I64u]: available = %I64u / %I64u\n", block_index, available_size, total_size);
					}
				//} else {
				//	printf("slice[%I64d] is missing.\n", slice_index);
				}
				slice_index = slice_list[slice_index].next;
				if ( (slice_index == -1) && (available_size < total_size) && (skip_count != old_count) ){
					//printf("block[%I64u]: skip_count = %I64u / %I64u, try again\n", block_index, skip_count, old_count);
					old_count = skip_count;
					skip_count = 0;

					// If a chunk tail was skipped, check again.
					slice_index = block_list[block_index].slice;
				}
			}

			// When whole data is available by all tail slices.
			if (available_size == total_size){
				block_list[block_index].state |= 16;
				block_available++;
			}
		}
	}

	return block_available;
}

// Aggregate recovery blocks of each Matrix Packet, and return the max count
uint64_t aggregate_recovery_block(PAR3_CTX *par3_ctx)
{
	uint8_t *packet_type, *buf;
	uint8_t packet_checksum[16];
	size_t offset, total_size;
	uint64_t item_index, packet_size, packet_count;
	uint64_t find_count, find_count_max;
	PAR3_PKT_CTX *packet_list;

	if (par3_ctx->matrix_packet_count == 0)
		return 0;
	if (par3_ctx->rec_data_packet_count == 0)
		return 0;

	buf = par3_ctx->matrix_packet;
	total_size = par3_ctx->matrix_packet_size;
	packet_list = par3_ctx->rec_data_packet_list;
	packet_count = par3_ctx->rec_data_packet_count;

	find_count_max = 0;
	offset = 0;
	while (offset + 48 < total_size){
		memcpy(packet_checksum, buf + offset + 8, 16);
		memcpy(&packet_size, buf + offset + 24, 8);
		packet_type = buf + offset + 40;

		// At this time, this supports only Reed-Solomon Erasure Codes with Cauchy Matrix.

		if (memcmp(packet_type, "PAR CAU\0", 8) == 0){	// Cauchy Matrix Packet
			// Search Recovery Data packet for this Matrix Packet
			find_count = 0;
			for (item_index = 0; item_index < packet_count; item_index++){
				if (memcmp(packet_list[item_index].matrix, packet_checksum, 16) == 0){
					find_count++;
				}
			}
			if (par3_ctx->noise_level >= 0){
				printf("You have %I64u recovery blocks available for Cauchy Matrix.\n", find_count);
			}
			if (find_count > find_count_max){
				find_count_max = find_count;
				par3_ctx->ecc_method |= 1;
				par3_ctx->matrix_packet_offset = offset;
			}
		}

		offset += packet_size;
	}

	return find_count_max;
}

