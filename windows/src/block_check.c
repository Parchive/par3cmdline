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
	if (par3_ctx->recv_packet_count == 0)
		return 0;

	buf = par3_ctx->matrix_packet;
	total_size = par3_ctx->matrix_packet_size;
	packet_list = par3_ctx->recv_packet_list;
	packet_count = par3_ctx->recv_packet_count;

	find_count_max = 0;
	offset = 0;
	while (offset + 48 < total_size){
		memcpy(packet_checksum, buf + offset + 8, 16);
		memcpy(&packet_size, buf + offset + 24, 8);
		packet_type = buf + offset + 40;

		// At this time, this supports only one Error Correction Codes at a time.

		if (memcmp(packet_type, "PAR CAU\0", 8) == 0){	// Cauchy Matrix Packet
			uint64_t hint_num;

			// Search Recovery Data packet for this Matrix Packet
			find_count = 0;
			for (item_index = 0; item_index < packet_count; item_index++){
				if (memcmp(packet_list[item_index].matrix, packet_checksum, 16) == 0){
					find_count++;
				}
			}
			// hint for number of recovery blocks
			memcpy(&hint_num, buf + offset + 64, 8);
			if (par3_ctx->noise_level >= 0){
				if (hint_num == 0){
					printf("You have %I64u recovery blocks available for Cauchy Reed-Solomon Codes.\n", find_count);
				} else {
					printf("You have %I64u / %I64u recovery blocks available for Cauchy Reed-Solomon Codes.\n", find_count, hint_num);
				}
			}
			if (find_count > find_count_max){
				find_count_max = find_count;
				par3_ctx->ecc_method = 1;	// At this time, exclusive to others.
				par3_ctx->max_recovery_block = hint_num;
				par3_ctx->matrix_packet_offset = offset;
			}

		} else if (memcmp(packet_type, "PAR FFT\0", 8) == 0){	// FFT Matrix Packet
			int8_t shift_num;
			uint32_t extra_num;
			uint64_t max_num;

			// Search Recovery Data packet for this Matrix Packet
			find_count = 0;
			for (item_index = 0; item_index < packet_count; item_index++){
				if (memcmp(packet_list[item_index].matrix, packet_checksum, 16) == 0){
					find_count++;
				}
			}
			// max number of recovery blocks
			shift_num = buf[offset + 64];	// convert to signed integer
			if ( (shift_num >= 0) && (shift_num <= 15) ){
				max_num = (uint64_t)1 << shift_num;
			} else {
				max_num = 32768;
			}
			// number of interleaving blocks
			extra_num = 0;
			if (packet_size > 65){
				if (packet_size == 66){	// 1 byte
					memcpy(&extra_num, buf + offset + 65, 1);
				} else if (packet_size == 67){	// 2 bytes
					memcpy(&extra_num, buf + offset + 65, 2);
				} else if (packet_size == 69){	// 4 bytes
					memcpy(&extra_num, buf + offset + 65, 4);
				}
				max_num *= extra_num + 1;	// When interleaving, max count is multiplied by number of cohorts.
			}
			if (par3_ctx->noise_level >= 0){
				if (find_count * 2 > max_num){
					printf("You have %I64u recovery blocks available for FFT based Reed-Solomon Codes.\n", find_count);
				} else {
					printf("You have %I64u / %I64u recovery blocks available for FFT based Reed-Solomon Codes.\n", find_count, max_num);
				}
			}
			if (par3_ctx->noise_level >= 1){
				if (extra_num > 0){
					printf("Number of cohorts = %u (Interleaving = %u)\n", extra_num + 1, extra_num);
					printf("Input block count per cohort = %I64u\n", (par3_ctx->block_count + extra_num) / (extra_num + 1));
					printf("Max recovery block count per cohort = %I64u\n", max_num / (extra_num + 1));
				}
			}
			if (find_count > find_count_max){
				find_count_max = find_count;
				par3_ctx->ecc_method = 8;
				par3_ctx->interleave = extra_num;
				par3_ctx->max_recovery_block = max_num;
				par3_ctx->matrix_packet_offset = offset;
			}

		}

		offset += packet_size;
	}

	return find_count_max;
}

// How many files to restore, when there are not enough blocks.
uint32_t check_possible_restore(PAR3_CTX *par3_ctx)
{
	char *find_name;
	uint32_t possible_count;
	uint32_t file_count, file_index;
	uint32_t chunk_index, chunk_num;
	int64_t slice_index;
	uint64_t block_size, chunk_size, file_size, slice_size;
	PAR3_SLICE_CTX *slice_list;
	PAR3_CHUNK_CTX *chunk_list;
	PAR3_FILE_CTX *file_list;

	if (par3_ctx->input_file_count == 0)
		return 0;

	file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	slice_list = par3_ctx->slice_list;
	chunk_list = par3_ctx->chunk_list;
	file_list = par3_ctx->input_file_list;

	possible_count = 0;
	for (file_index = 0; file_index < file_count; file_index++){
		// This input file is misnamed.
		if (file_list[file_index].state & 4){
			// Misnamed file will be corrected later.
			//printf("misnamed file[%u]\n", file_index);
			possible_count++;

		// The input file is missing or damaged.
		} else if (file_list[file_index].state & 3){
			file_size = 0;
			chunk_index = file_list[file_index].chunk;		// index of the first chunk
			chunk_num = file_list[file_index].chunk_num;	// number of chunk descriptions
			slice_index = file_list[file_index].slice;		// index of the first slice
			//printf("chunk = %u+%u, slice = %I64d ~, %s\n", chunk_index, chunk_num, slice_index, file_list[file_index].name);
			while (chunk_num > 0){
				chunk_size = chunk_list[chunk_index].size;
				file_size += chunk_size;
				while ( (chunk_size >= block_size) || (chunk_size >= 40) ){	// full size slice or chunk tail slice
					slice_size = slice_list[slice_index].size;
					find_name = slice_list[slice_index].find_name;
					if (find_name == NULL){
						//printf("slice[%I64d] isn't found.\n", slice_index);
						file_size--;
						chunk_num = 1;
						break;
					}

					slice_index++;
					chunk_size -= slice_size;
				}

				chunk_index++;
				chunk_num--;
			}

			//printf("file_size = %I64u, %I64u\n", file_size, file_list[file_index].size);
			if (file_size == file_list[file_index].size){
				// Sign of repairable file
				file_list[file_index].state |= 0x200;
				possible_count++;
			}
		}
	}
	//printf("possible_count = %u\n", possible_count);

	return possible_count;
}

// Make list of index for lost input blocks and using recovery blocks.
int make_block_list(PAR3_CTX *par3_ctx, uint64_t lost_count, uint32_t lost_count_cohort)
{
	uint8_t *packet_checksum;
	int *recv_id;
	uint64_t count, index, id;
	PAR3_BLOCK_CTX *block_list;
	PAR3_PKT_CTX *packet_list;

	if (par3_ctx->ecc_method & 1){	// Cauchy Reed-Solomon Codes
		// Make list of index (lost input blocks and using recovery blocks)
		count = lost_count * 2;
	} else if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
		if (par3_ctx->interleave == 0){
			// Make list of index (using recovery blocks)
			count = lost_count;
		} else {
			// Make list of index (position)
			count = lost_count_cohort;
		}
	} else {
		// Make list of index (using recovery blocks)
		count = lost_count;
	}
	recv_id = (int *) malloc(sizeof(int) * count);
	if (recv_id == NULL){
		printf("Failed to make list for using blocks\n");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->recv_id_list = recv_id;

	if (par3_ctx->interleave > 0)
		return 0;

	// Get checksum of using Matrix Packet
	packet_checksum = par3_ctx->matrix_packet + par3_ctx->matrix_packet_offset + 8;

	// Set index of using recovery blocks
	packet_list = par3_ctx->recv_packet_list;
	count = par3_ctx->recv_packet_count;
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

	if (par3_ctx->ecc_method & 1){	// Cauchy Reed-Solomon Codes
		int *lost_id = recv_id + lost_count;

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
	}

	return 0;
}

// Aggregate input blocks and recovery blocks of each cohort, and return lacking count;
uint64_t aggregate_block_cohort(PAR3_CTX *par3_ctx, uint32_t *lost_count_cohort)
{
	uint8_t *packet_checksum;
	uint32_t cohort_count, cohort_index;
	uint32_t lack_count, lack_count_max, lack_count_min;
	uint32_t lost_count_max, lost_count_min;
	uint32_t recv_count_max, recv_count_min;
	uint32_t *lost_list, *recv_list;
	uint64_t count, index, id, lack_count_total;
	PAR3_BLOCK_CTX *block_list;
	PAR3_PKT_CTX *packet_list;

	cohort_count = par3_ctx->interleave + 1;

	// Allocate memory and zero fill
	lost_list = (uint32_t *) calloc(cohort_count * 2, sizeof(uint32_t));
	recv_list = lost_list + cohort_count;
	par3_ctx->lost_list = lost_list;	// Store here to refer and release later

	// Get checksum of using Matrix Packet
	packet_checksum = par3_ctx->matrix_packet + par3_ctx->matrix_packet_offset + 8;

	// Check index of using recovery blocks
	packet_list = par3_ctx->recv_packet_list;
	count = par3_ctx->recv_packet_count;
	for (index = 0; index < count; index++){
		// Search only Recovery Data Packets belong to using Matrix Packet
		if (memcmp(packet_list[index].matrix, packet_checksum, 16) == 0){
			id = packet_list[index].index;
			//printf("recv_packet[%I64u] = %I64u, ", index, id);
			id %= cohort_count;	// modulo
			recv_list[id] += 1;
			//printf("recv_list[%I64u] = %I64u\n", id, recv_list[id]);
		}
	}

	// Check index of lost input blocks
	block_list = par3_ctx->block_list;
	count = par3_ctx->block_count;
	for (index = 0; index < count; index++){
		if ((block_list[index].state & (4 | 16)) == 0){
			id = index % cohort_count;
			lost_list[id] += 1;
			//printf("lost block[%I64u] : lost_list[%I64u] = %u\n", index, id, lost_list[id]);
		}
	}

	// Check each cohort
	lack_count_total = 0;
	lack_count_max = 0;
	lack_count_min = UINT_MAX;
	lost_count_max = 0;
	lost_count_min = UINT_MAX;
	recv_count_max = 0;
	recv_count_min = UINT_MAX;
	for (cohort_index = 0; cohort_index < cohort_count; cohort_index++){
		if (lost_list[cohort_index] > recv_list[cohort_index]){
			// If number of lost blocks is larger than number of recovery blocks, sum the value.
			lack_count = lost_list[cohort_index] - recv_list[cohort_index];
			lack_count_total += lack_count;
			if (lack_count_max < lack_count)
				lack_count_max = lack_count;
			if (lack_count_min > lack_count)
				lack_count_min = lack_count;
		} else {
			lack_count_min = 0;	// This cohort is locally repairable.
		}
		if (lost_count_max < lost_list[cohort_index])
			lost_count_max = lost_list[cohort_index];
		if (lost_count_min > lost_list[cohort_index])
			lost_count_min = lost_list[cohort_index];
		if (recv_count_max < recv_list[cohort_index])
			recv_count_max = recv_list[cohort_index];
		if (recv_count_min > recv_list[cohort_index])
			recv_count_min = recv_list[cohort_index];
	}
	// Use these values at repair
	if (lost_count_cohort != NULL)
		*lost_count_cohort = lost_count_max;
	if (par3_ctx->noise_level >= 1){
		// Show min & max numbers of recovery blocks and lost input blocks among cohorts.
		printf("Recovery block count among cohorts  = %u ~ %u\n", recv_count_min, recv_count_max);
		printf("Lost block count among cohorts      = %u ~ %u\n", lost_count_min, lost_count_max);
		if (lack_count_total > 0){
			// Show numbers of required recovery blocks among cohorts.
			printf("Required block count among cohorts  = %u ~ %u\n", lack_count_min, lack_count_max);
		}
	}

	return lack_count_total;
}

