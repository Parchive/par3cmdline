#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__

#include <limits.h>

#elif _WIN32
#endif

#include "libpar3.h"
#include "common.h"


// Count how many number of input file slices, and allocate memory for them.
int count_slice_info(PAR3_CTX *par3_ctx)
{
	uint32_t chunk_count;
	uint64_t block_size, chunk_size, tail_size;
	uint64_t block_count, slice_count;
	PAR3_CHUNK_CTX *chunk_p;
	PAR3_BLOCK_CTX *block_p;
	PAR3_SLICE_CTX *slice_p;

	// Copy variables from context to local.
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	chunk_count = par3_ctx->chunk_count;
	chunk_p = par3_ctx->chunk_list;
	if ( (chunk_count == 0) || (block_size == 0) || (block_count == 0) )
		return RET_LOGIC_ERROR;

	slice_count = 0;
	while (chunk_count > 0){
		chunk_size = chunk_p->size;
		if (chunk_size != 0){
			if (chunk_size >= block_size){
				slice_count += chunk_size / block_size;
				tail_size = chunk_size % block_size;
			} else {
				tail_size = chunk_size;
			}
			if (tail_size >= 40)
				slice_count++;
		}

		chunk_p++;
		chunk_count--;
	}

	par3_ctx->slice_count = slice_count;
	if (par3_ctx->noise_level >= 2){
		printf("Number of input file slice = %"PRIu64"\n", slice_count);
	}

	// Allocate memory for block and slice info.
	if (par3_ctx->slice_list != NULL)
		free(par3_ctx->slice_list);
	par3_ctx->slice_list = malloc(sizeof(PAR3_SLICE_CTX) * slice_count);
	if (par3_ctx->slice_list == NULL){
		perror("Failed to allocate memory for input file slices");
		return RET_MEMORY_ERROR;
	}
	if (par3_ctx->block_list != NULL)
		free(par3_ctx->block_list);
	par3_ctx->block_list = malloc(sizeof(PAR3_BLOCK_CTX) * block_count);
	if (par3_ctx->block_list == NULL){
		perror("Failed to allocate memory for input blocks");
		return RET_MEMORY_ERROR;
	}

	// Initialize slice info.
	slice_p = par3_ctx->slice_list;
	while (slice_count > 0){
		slice_p->next = -1;
		slice_p->find_name = NULL;
		slice_p->find_offset = 0;

		slice_p++;
		slice_count--;
	}

	// Initialize block info.
	block_p = par3_ctx->block_list;
	while (block_count > 0){
		block_p->slice = -1;
		block_p->size = 0;
		block_p->crc = 0;
		memset(block_p->hash, 0, 16);
		block_p->state = 0;

		block_p++;
		block_count--;
	}

	return 0;
}

int set_slice_info(PAR3_CTX *par3_ctx)
{
	uint32_t num, num_pack, input_file_count;
	uint32_t chunk_count, chunk_index, chunk_num;
	int64_t index;
	uint64_t block_size, chunk_size;
	uint64_t block_count, file_offset, tail_offset;
	uint64_t slice_count, slice_index, block_index;
	uint64_t num_dedup;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_p;
	PAR3_SLICE_CTX *slice_p, *slice_list;
	PAR3_BLOCK_CTX *block_list;

	// Copy variables from context to local.
	input_file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	block_count = par3_ctx->block_count;
	chunk_count = par3_ctx->chunk_count;
	slice_count = par3_ctx->slice_count;
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;
	slice_p = slice_list;

	num_dedup = 0;
	num_pack = 0;
	slice_index = 0;
	file_p = par3_ctx->input_file_list;
	for (num = 0; num < input_file_count; num++){
		if (file_p->size == 0){	// Skip empty files.
			file_p++;
			continue;
		}

		file_offset = 0;
		chunk_index = file_p->chunk;	// index of the first chunk
		chunk_num = file_p->chunk_num;	// number of chunk descriptions
		file_p->slice = slice_index;	// index of the first slice
		if (par3_ctx->noise_level >= 3){
			printf("chunk = %u + %u, slice = %"PRIu64", file size = %"PRIu64" \"%s\"\n",
					chunk_index, chunk_num, slice_index, file_p->size, file_p->name);
		}

		while (chunk_num > 0){	// check all chunk descriptions
			if (chunk_index >= chunk_count){
				printf("There are too many chunk descriptions. %u\n", chunk_index);
				return RET_LOGIC_ERROR;
			}
			chunk_p = par3_ctx->chunk_list + chunk_index;
			chunk_size = chunk_p->size;
			if (chunk_size == 0){	// Unprotected Chunk Description
				file_offset += chunk_p->block;
				if (par3_ctx->noise_level >= 3){
					printf("unprotected chunk size = %"PRIu64"\n", chunk_p->block);
				}

			} else {	// Protected Chunk Description
				block_index = chunk_p->block;	// index of first input block holding chunk
				if (par3_ctx->noise_level >= 3){
					printf("chunk size = %"PRIu64", first block = %"PRIu64"\n", chunk_size, block_index);
				}

				while (chunk_size >= block_size){
					if (slice_index >= slice_count){
						printf("There are too many input file slices. %"PRIu64"\n", slice_index);
						return RET_LOGIC_ERROR;
					}
					if (block_index >= block_count){
						printf("There are too many input blocks. %"PRIu64"\n", block_index);
						return RET_LOGIC_ERROR;
					}
					index = block_list[block_index].slice;
					if (index != -1){
						// If slice info was set elready, it's a same block.
						while (slice_list[index].next != -1){
							index = slice_list[index].next;
						}
						slice_list[index].next = slice_index;
						num_dedup++;
						if (par3_ctx->noise_level >= 3){
							printf("old block[%2"PRIu64"] : slice[%2"PRIu64"] chunk[%2u] file %d, offset %"PRIu64"\n",
									block_index, slice_index, chunk_index, num, file_offset);
						}

					} else {
						block_list[block_index].slice = slice_index;
						block_list[block_index].size = block_size;
						block_list[block_index].state |= 1;
						if (par3_ctx->noise_level >= 3){
							printf("new block[%2"PRIu64"] : slice[%2"PRIu64"] chunk[%2u] file %d, offset %"PRIu64"\n",
									block_index, slice_index, chunk_index, num, file_offset);
						}
					}

					// set slice info
					slice_p->chunk = chunk_index;
					slice_p->file = num;
					slice_p->offset = file_offset;
					slice_p->size = block_size;
					slice_p->block = block_index;
					slice_p->tail_offset = 0;
					slice_p++;
					slice_index++;

					block_index++;
					file_offset += block_size;
					chunk_size -= block_size;
				}
				if (chunk_size >= 40){	// Chunk tail size is equal or larger than 40 bytes.
					if (slice_index >= slice_count){
						printf("There are too many input file slices. %"PRIu64"\n", slice_index);
						return RET_LOGIC_ERROR;
					}
					block_index = chunk_p->tail_block;	// index of block holding tail
					if (block_index >= block_count){
						printf("There are too many input blocks. %"PRIu64"\n", block_index);
						return RET_LOGIC_ERROR;
					}
					tail_offset = chunk_p->tail_offset;
					if (tail_offset + chunk_size > block_size){
						printf("Chunk tail exceeds block size. %"PRIu64" + %"PRIu64"\n", tail_offset, chunk_size);
						return RET_LOGIC_ERROR;
					}
					//printf("tail size = %"PRIu64", belong block = %"PRIu64", offset = %"PRIu64"\n", chunk_size, block_index, tail_offset);

					index = block_list[block_index].slice;
					if (index != -1){
						// Search slice info to find same tail.
						do {
							//printf("slice[%2"PRIu64"].size = %"PRIu64", tail_offset = %"PRIu64"\n", index, slice_list[index].size, slice_list[index].tail_offset);
							if ( (slice_list[index].size == chunk_size) && (slice_list[index].tail_offset == tail_offset) ){
								break;
							}
							index = slice_list[index].next;
						} while (index != -1);

						if (index != -1){
							num_dedup++;
							if (par3_ctx->noise_level >= 3){
								printf("o t block[%2"PRIu64"] : slice[%2"PRIu64"] chunk[%2u] file %d, offset %"PRIu64", tail size %"PRIu64", offset %"PRIu64"\n",
										block_index, slice_index, chunk_index, num, file_offset, chunk_size, tail_offset);
							}
						} else {
							num_pack++;
							if (block_list[block_index].size < tail_offset + chunk_size)
								block_list[block_index].size = tail_offset + chunk_size;
							if (par3_ctx->noise_level >= 3){
								printf("a t block[%2"PRIu64"] : slice[%2"PRIu64"] chunk[%2u] file %d, offset %"PRIu64", tail size %"PRIu64", offset %"PRIu64"\n",
										block_index, slice_index, chunk_index, num, file_offset, chunk_size, tail_offset);
							}
						}

						// If slice info was set elready, it may be a chunk tail in the same block.
						index = block_list[block_index].slice;
						while (slice_list[index].next != -1){
							index = slice_list[index].next;
						}
						slice_list[index].next = slice_index;
						//printf("slice[%2"PRIu64"].next = %"PRIu64"\n", index, slice_index);

					} else {
						block_list[block_index].slice = slice_index;
						block_list[block_index].size = tail_offset + chunk_size;
						block_list[block_index].state |= 2;
						if (par3_ctx->noise_level >= 3){
							printf("n t block[%2"PRIu64"] : slice[%2"PRIu64"] chunk[%2u] file %d, offset %"PRIu64", tail size %"PRIu64", offset %"PRIu64"\n",
									block_index, slice_index, chunk_index, num, file_offset, chunk_size, tail_offset);
						}
					}

					// set slice info
					slice_p->chunk = chunk_index;
					slice_p->file = num;
					slice_p->offset = file_offset;
					slice_p->size = chunk_size;
					slice_p->block = block_index;
					slice_p->tail_offset = tail_offset;
					slice_p++;
					slice_index++;

				} else if (chunk_size > 0){	// Chunk tail size = 1~39 bytes.
					if (par3_ctx->noise_level >= 3){
						printf("    block no  : slice no  chunk[%2u] file %d, offset %"PRIu64", tail size %"PRIu64"\n",
								chunk_index, num, file_offset, chunk_size);
					}

				}
				file_offset += chunk_size;	// tail size
			}

			chunk_index++;	// goto next chunk
			chunk_num--;
		}

		file_p++;
	}

	// Check every block has own slice.
	for (block_index = 0; block_index < block_count; block_index++){
		if (block_list[block_index].slice == -1){
			printf("There is no slice for input block[%"PRIu64"].\n", block_index);
			return RET_INSUFFICIENT_DATA;
		}
	}

	// Check actual number of slices.
	if (slice_index != slice_count){
		printf("Number of input file slice = %"PRIu64" (max %"PRIu64")\n", slice_index, slice_count);
		return RET_LOGIC_ERROR;
	}
	if (par3_ctx->noise_level >= 0){
		printf("Tail packing = %u, Deduplication = %"PRIu64"\n", num_pack, num_dedup);
	}

	return 0;
}

// Calculate creating amount of recovery blocks from given redundancy
int calculate_recovery_count(PAR3_CTX *par3_ctx)
{
	uint64_t total_count;

	if (par3_ctx->block_count == 0){
		par3_ctx->ecc_method = 0;
		par3_ctx->redundancy_size = 0;
		par3_ctx->recovery_block_count = 0;
		par3_ctx->max_recovery_block = 0;
		par3_ctx->interleave = 0;
		return 0;	// There is no input block.
	} else if (par3_ctx->ecc_method == 0){
		// When using algothim was not specified.
		par3_ctx->ecc_method = 1;	// At this time, select Cauchy Reed-Solomon Codes by default.
	}

	if ( (par3_ctx->recovery_block_count == 0) && (par3_ctx->redundancy_size == 0) )
		return 0;	// Not specified

	// When number of recovery blocks was not specified, set by redundancy.
	if ( (par3_ctx->recovery_block_count == 0) && (par3_ctx->redundancy_size > 0) ){
		// If redundancy_size is in range (0 ~ 250), it's a percent rate value.
		if (par3_ctx->redundancy_size <= 250){
			// When there is remainder at division, round up the quotient.
			par3_ctx->recovery_block_count = (par3_ctx->block_count * par3_ctx->redundancy_size + 99) / 100;
		}
	}
	if ( (par3_ctx->max_recovery_block == 0) && (par3_ctx->max_redundancy_size > 0) ){
		if (par3_ctx->max_redundancy_size <= 250){
			par3_ctx->max_recovery_block = (par3_ctx->block_count * par3_ctx->max_redundancy_size + 99) / 100;
		}
	}

	// Test number of blocks
	if (par3_ctx->ecc_method & 1){	// Cauchy Reed-Solomon Codes
		if (par3_ctx->noise_level >= 0){
			printf("Cauchy Reed-Solomon Codes\n");
		}

		// When max recovery block count is set, it must be equal or larger than creating recovery blocks.
		if ((par3_ctx->max_recovery_block > 0) && (par3_ctx->max_recovery_block < par3_ctx->recovery_block_count))
			par3_ctx->max_recovery_block = par3_ctx->recovery_block_count;

		// Check total number of blocks
		total_count = par3_ctx->block_count + par3_ctx->first_recovery_block + par3_ctx->recovery_block_count;
		if (total_count < par3_ctx->block_count + par3_ctx->max_recovery_block)
			total_count = par3_ctx->block_count + par3_ctx->max_recovery_block;
		if (total_count > 65536){
			printf("Total block count %"PRIu64" are too many.\n", total_count);
			return RET_LOGIC_ERROR;
		}

		if (par3_ctx->noise_level >= 0){
			printf("Recovery block count = %"PRIu64"\n", par3_ctx->recovery_block_count);
			if (par3_ctx->max_recovery_block > 0){
				printf("Max recovery block count = %"PRIu64"\n", par3_ctx->max_recovery_block);
			}
			printf("\n");
		}

	} else if (par3_ctx->ecc_method & 8){	// FFT based Reed-Solomon Codes
		uint64_t cohort_count, i;

		if (par3_ctx->noise_level >= 0){
			printf("FFT based Reed-Solomon Codes\n");
		}

		// Caution ! Too many interleaving is bad for recovery.
		// Number of cohort must be equal or less than number of input blocks.
		cohort_count = par3_ctx->interleave + 1; // Minimum value is 1.
		if (cohort_count > par3_ctx->block_count){
			cohort_count = par3_ctx->block_count;
			printf("Number of cohort is decreased to %"PRIu64".\n", cohort_count);
		}

		// When there are too many block, it uses interleaving automatically.
		if (cohort_count == 1){
			// Check total number of blocks
			total_count = par3_ctx->block_count + par3_ctx->first_recovery_block + par3_ctx->recovery_block_count;
			if (total_count < par3_ctx->block_count + par3_ctx->max_recovery_block)
				total_count = par3_ctx->block_count + par3_ctx->max_recovery_block;
			if (total_count > 65536){
				cohort_count = (total_count + 65536 - 1) / 65536;
				printf("Number of cohort is increased to %"PRIu64".\n", cohort_count);
			}
			total_count = par3_ctx->first_recovery_block + par3_ctx->recovery_block_count;
			if (total_count < par3_ctx->max_recovery_block)
				total_count = par3_ctx->max_recovery_block;
			if (total_count > 32768 * cohort_count){
				cohort_count = (total_count + 32768 - 1) / 32768;
				printf("Number of cohort is increased to %"PRIu64".\n", cohort_count);
			}
		}

		if (cohort_count > UINT_MAX){
			printf("There are too many cohorts %"PRIu64".\n", cohort_count);
			return RET_LOGIC_ERROR;
		}
		if (cohort_count > 1){
			par3_ctx->interleave = (uint32_t)(cohort_count - 1);
			if (par3_ctx->noise_level >= 0){
				printf("Number of cohort = %"PRIu64" (Interleaving time = %u)\n", cohort_count, par3_ctx->interleave);
				i = (par3_ctx->block_count + cohort_count - 1) / cohort_count;	// round up
				printf("Input block count = %"PRIu64" (%"PRIu64" per cohort)\n", par3_ctx->block_count, i);
			}
		}

		// Number of recovery block will be multiple of number of cohorts.
		i = par3_ctx->recovery_block_count % cohort_count;
		if (i > 0){
			if (par3_ctx->noise_level >= 1){
				printf("Recovery block count is increased from %"PRIu64" to %"PRIu64"\n", par3_ctx->recovery_block_count, par3_ctx->recovery_block_count + cohort_count - i);
			}
			par3_ctx->recovery_block_count += cohort_count - i;	// add to the remainder
		}
		if (par3_ctx->max_recovery_block > 0){
			// When max recovery block count is set, it must be equal or larger than creating recovery blocks.
			if (par3_ctx->max_recovery_block < par3_ctx->recovery_block_count)
				par3_ctx->max_recovery_block = par3_ctx->recovery_block_count;
			i = par3_ctx->max_recovery_block % cohort_count;
			if (i > 0)
				par3_ctx->max_recovery_block += cohort_count - i;	// add to the remainder
		}
		// First recovery block will be lower.
		i = par3_ctx->first_recovery_block % cohort_count;
		if (i > 0){
			if (par3_ctx->noise_level >= 1){
				printf("First recovery block is decreased from %"PRIu64" to %"PRIu64"\n", par3_ctx->first_recovery_block, par3_ctx->first_recovery_block - i);
			}
			par3_ctx->first_recovery_block -= i;	// erase the remainder
		}

		// Check total number of blocks
		total_count = par3_ctx->block_count + par3_ctx->first_recovery_block + par3_ctx->recovery_block_count;
		if (total_count < par3_ctx->block_count + par3_ctx->max_recovery_block)
			total_count = par3_ctx->block_count + par3_ctx->max_recovery_block;
		if (total_count > 65536 * cohort_count){
			if (cohort_count == 1){
				printf("Total block count %"PRIu64" are too many.\n", total_count);
			} else {
				i = (total_count + cohort_count - 1) / cohort_count;	// round up
				printf("Total block count %"PRIu64" (%"PRIu64" per cohort) are too many.\n", total_count, i);
			}
			return RET_LOGIC_ERROR;
		}
		// Leopard-RS library has a restriction; recovery_count <= 32768
		// Though it's possible to solve this problem, I don't try at this time.
		total_count = par3_ctx->first_recovery_block + par3_ctx->recovery_block_count;
		if (total_count < par3_ctx->max_recovery_block)
			total_count = par3_ctx->max_recovery_block;
		if (total_count > 32768 * cohort_count){
			if (cohort_count == 1){
				printf("Recovery block count %"PRIu64" are too many.\n", total_count);
			} else {
				printf("Recovery block count %"PRIu64" (%"PRIu64" per cohort) are too many.\n", total_count, total_count / cohort_count);
			}
			return RET_LOGIC_ERROR;
		}

		if (par3_ctx->noise_level >= 0){
			if (cohort_count == 1){
				printf("Recovery block count = %"PRIu64"\n", par3_ctx->recovery_block_count);
			} else {
				printf("Recovery block count = %"PRIu64" (%"PRIu64" per cohort)\n", par3_ctx->recovery_block_count, par3_ctx->recovery_block_count / cohort_count);
			}
			if (par3_ctx->max_recovery_block > 0){
				if (cohort_count == 1){
					printf("Max recovery block count = %"PRIu64"\n", par3_ctx->max_recovery_block);
				} else {
					printf("Max recovery block count = %"PRIu64" (%"PRIu64" per cohort)\n", par3_ctx->max_recovery_block, par3_ctx->max_recovery_block / cohort_count);
				}
			}
			printf("\n");
		}

	} else {
		printf("The specified Error Correction Codes (%u) isn't implemented yet.\n", par3_ctx->ecc_method);
		return RET_LOGIC_ERROR;
	}

	return 0;
}
