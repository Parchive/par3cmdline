#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "block.h"
#include "packet.h"
#include "read.h"
#include "verify.h"
#include "write.h"


// Check Matrix Packet in refered PAR file.
static int check_matrix_packet(PAR3_CTX *par3_ctx)
{
	uint8_t *packet_type, *buf;
	size_t offset, total_size;
	uint64_t packet_size;

	printf("\n");
	if (par3_ctx->matrix_packet_count == 0)
		return 0;

	buf = par3_ctx->matrix_packet;
	total_size = par3_ctx->matrix_packet_size;

	offset = 0;
	while (offset + 48 < total_size){
		memcpy(&packet_size, buf + offset + 24, 8);
		packet_type = buf + offset + 40;

		// At this time, this supports only one Error Correction Codes at a time.
		// Return the first found one.

		if (memcmp(packet_type, "PAR CAU\0", 8) == 0){	// Cauchy Matrix Packet
			uint64_t first_num, last_num, hint_num;

			// Read numbers
			memcpy(&first_num, buf + offset + 48, 8);
			memcpy(&last_num, buf + offset + 56, 8);
			memcpy(&hint_num, buf + offset + 64, 8);
			if (par3_ctx->noise_level >= 1){
				printf("Cauchy Matrix Packet:\n");
				printf("Index of first input block         = %"PRIu64"\n", first_num);
				printf("Index of last input block plus 1   = %"PRIu64"\n", last_num);
				printf("hint for number of recovery blocks = %"PRIu64"\n", hint_num);
				printf("\n");
			}

			// Return error, if par3cmdline doesn't support the given number.
			if (first_num != 0){
				printf("Compatibility issue: Index of first input block\n");
				return RET_LOGIC_ERROR;
			}
			if (last_num != 0){
				printf("Compatibility issue: Index of last input block\n");
				return RET_LOGIC_ERROR;
			}

			// Return error, if read number is different from specified option.
			if ( (par3_ctx->ecc_method != 0) && (par3_ctx->ecc_method != 1) ){
				printf("Compatibility issue: Error Correction Codes is different.\n");
				return RET_INVALID_COMMAND;
			}
			if ( (par3_ctx->max_recovery_block != 0) || (par3_ctx->max_redundancy_size != 0) ){
				printf("Compatibility issue: Max number of recovery blocks.\n");
				return RET_INVALID_COMMAND;
			}

			par3_ctx->ecc_method = 1;
			par3_ctx->max_recovery_block = hint_num;
			par3_ctx->matrix_packet_offset = offset;
			return -1;

		} else if (memcmp(packet_type, "PAR FFT\0", 8) == 0){	// FFT Matrix Packet
			int8_t shift_num;
			uint32_t extra_num;
			uint64_t first_num, last_num, max_num;

			// Read numbers
			memcpy(&first_num, buf + offset + 48, 8);
			memcpy(&last_num, buf + offset + 56, 8);
			shift_num = buf[offset + 64];	// convert to signed integer
			if ( (shift_num >= 0) && (shift_num <= 15) ){
				max_num = (uint64_t)1 << shift_num;
			} else {
				max_num = 32768;
			}
			extra_num = 0;
			if ((packet_size > 65) && (packet_size <= 69)){	// Read 1 ~ 4 bytes of the last field
				memcpy(&extra_num, buf + offset + 65, packet_size - 65);
			}
			if (par3_ctx->noise_level >= 1){
				printf("FFT Matrix Packet:\n");
				printf("Index of first input block       = %"PRIu64"\n", first_num);
				printf("Index of last input block plus 1 = %"PRIu64"\n", last_num);
				printf("Max number of recovery blocks    = %"PRIu64"\n", max_num);
				printf("Number of interleaving blocks    = %u\n", extra_num);
				printf("\n");
			}

			// Return error, if par3cmdline doesn't support the given number.
			if (first_num != 0){
				printf("Compatibility issue: Index of first input block\n");
				return RET_LOGIC_ERROR;
			}
			if (last_num != 0){
				printf("Compatibility issue: Index of last input block\n");
				return RET_LOGIC_ERROR;
			}

			// Return error, if read number is different from specified option.
			if ( (par3_ctx->ecc_method != 0) && (par3_ctx->ecc_method != 8) ){
				printf("Compatibility issue: Error Correction Codes is different.\n");
				return RET_INVALID_COMMAND;
			}
			if ( (par3_ctx->max_recovery_block != 0) || (par3_ctx->max_redundancy_size != 0) ){
				printf("Compatibility issue: Max number of recovery blocks.\n");
				return RET_INVALID_COMMAND;
			}
			if ( (par3_ctx->interleave != 0) && (par3_ctx->interleave != extra_num) ){
				printf("Compatibility issue: Number of interleaving is different.\n");
				return RET_INVALID_COMMAND;
			}

			par3_ctx->ecc_method = 8;
			par3_ctx->interleave = extra_num;
			par3_ctx->max_recovery_block = max_num * (extra_num + 1);	// When interleaving, max count is multiplied by number of cohorts.
			par3_ctx->matrix_packet_offset = offset;
			return -8;

		}

		offset += packet_size;
	}

	return 0;
}

// Calculate extending amount of recovery blocks from given redundancy
static int calculate_extra_count(PAR3_CTX *par3_ctx)
{
	uint64_t total_count;

	if (par3_ctx->block_count == 0){
		par3_ctx->ecc_method = 0;
		par3_ctx->redundancy_size = 0;
		par3_ctx->recovery_block_count = 0;
		return 0;	// There is no input block.
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

		// Reuse previous settings
		cohort_count = par3_ctx->interleave + 1; // Minimum value is 1.
		if (cohort_count > 1){
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


int par3_extend(PAR3_CTX *par3_ctx, char command_trial, char *temp_path)
{
	int ret;
	uint32_t missing_file_count, damaged_file_count, bad_file_count;

	ret = read_packet(par3_ctx);
	if (ret != 0)
		return ret;

	ret = parse_vital_packet(par3_ctx);
	if (ret != 0)
		return ret;

	// Show archived file data.
	if (par3_ctx->noise_level >= 0)
		show_data_size(par3_ctx);
	if (par3_ctx->noise_level == 1){
		show_read_result(par3_ctx, 1);
	} else if (par3_ctx->noise_level >= 2){
		show_read_result(par3_ctx, 2);
	}

	// Map input file slices into blocks
	if (par3_ctx->block_count > 0){
		ret = count_slice_info(par3_ctx);
		if (ret != 0)
			return ret;

		ret = set_slice_info(par3_ctx);
		if (ret != 0)
			return ret;

		ret = parse_external_data_packet(par3_ctx);
		if (ret != 0)
			return ret;
	}

	// Check input file
	missing_file_count = 0;
	damaged_file_count = 0;
	bad_file_count = 0;
	ret = verify_input_file(par3_ctx, &missing_file_count, &damaged_file_count, &bad_file_count);
	if (ret != 0)
		return ret;

	// It's possible to create recovery blocks, only when all input files are complete.
	// Ignore different timestamp or property.
	if (missing_file_count + damaged_file_count > 0){
		printf("\n");
		printf("%u files are missing or damaged.\n", missing_file_count + damaged_file_count);
		return RET_REPAIR_NOT_POSSIBLE;
	}

	// Check Matrix Packet to create compatible recovery blocks.
	ret = check_matrix_packet(par3_ctx);
	if (ret < 0){	// Use previous settings in found Matrix Packet
		ret = calculate_extra_count(par3_ctx);
		if (ret != 0)
			return ret;

	} else if (ret == 0){	// Adopt options in command-line
		ret = calculate_recovery_count(par3_ctx);
		if (ret != 0)
			return ret;

		// Make new Matrix Packet
		if (par3_ctx->recovery_block_count > 0){
			ret = make_matrix_packet(par3_ctx);
			if (ret != 0)
				return ret;
		}
		/*
		{	// Debug output to compare result
			FILE *fp;
			fp = fopen("debug.txt", "wb");
			if (fp != NULL){
				fwrite(par3_ctx->matrix_packet, 1, par3_ctx->matrix_packet_size, fp);
				fclose(fp);
			}
		}
		*/

	} else {
		return ret;
	}

	if (command_trial != 0){
		uint64_t total_par_size;	// This is a dummy item, when it doesn't show efficiency rate.

		// Try Index File
		total_par_size = try_index_file(par3_ctx);

		// Try other PAR3 files
		if ( (par3_ctx->block_count > 0) && ( (par3_ctx->data_packet != 0) || (par3_ctx->recovery_block_count > 0) ) ){
			ret = duplicate_common_packet(par3_ctx);
			if (ret != 0)
				return ret;

			// Write PAR3 files with input blocks
			if (par3_ctx->data_packet != 0){
				ret = try_archive_file(par3_ctx, temp_path, &total_par_size);
				if (ret != 0)
					return ret;
			}

			// Write PAR3 files with recovery blocks
			if (par3_ctx->recovery_block_count > 0){
				ret = try_recovery_file(par3_ctx, temp_path, &total_par_size);
				if (ret != 0)
					return ret;
			}
		}

		// Because a user cannot change setting to create extra recovery blocks,
		// showing efficiency rate will be useless.
		//printf("\nTotal size of PAR files = %"PRIu64"\n", total_par_size);

	} else {
		// Write Index File
		ret = write_index_file(par3_ctx);
		if (ret != 0)
			return ret;

		// Write other PAR3 files
		if ( (par3_ctx->block_count > 0) && ( (par3_ctx->data_packet != 0) || (par3_ctx->recovery_block_count > 0) ) ){
			ret = duplicate_common_packet(par3_ctx);
			if (ret != 0)
				return ret;

			// When it uses Reed-Solomon Erasure Codes, it tries to keep all recovery blocks on memory.
			if (par3_ctx->ecc_method & 1){
				ret = allocate_recovery_block(par3_ctx);
				if (ret != 0)
					return ret;
			}

			// Write PAR3 files with input blocks
			if (par3_ctx->data_packet != 0){
				ret = write_archive_file(par3_ctx, temp_path);
				if (ret != 0)
					return ret;
			}

			// If there are enough memory to keep all recovery blocks,
			// it calculates recovery blocks before writing Recovery Data Packets.
			if (par3_ctx->ecc_method & 0x8000){
				ret = create_recovery_block(par3_ctx);
				if (ret < 0){
					par3_ctx->ecc_method &= ~0x8000;
				} else if (ret > 0){
					return ret;
				}
			}

			// Write PAR3 files with recovery blocks
			if (par3_ctx->recovery_block_count > 0){
				ret = write_recovery_file(par3_ctx, temp_path);
				if (ret != 0){
					//remove_recovery_file(par3_ctx);	// Remove partially created files
					return ret;
				}
			}

			// When recovery blocks were not created yet, calculate and write at here.
			if ((par3_ctx->ecc_method & 0x8000) == 0){
				if ( (par3_ctx->ecc_method & 8) && (par3_ctx->interleave > 0) ){
					// Interleaving is adapted only for FFT based Reed-Solomon Codes.
					ret = create_recovery_block_cohort(par3_ctx);
				} else {
					ret = create_recovery_block_split(par3_ctx);
				}
				if (ret != 0){
					//remove_recovery_file(par3_ctx);	// Remove partially created files
					return ret;
				}
			}
		}
	}

	return 0;
}

