// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpar3.h"
#include "block.h"
#include "packet.h"
#include "read.h"
#include "repair.h"
#include "verify.h"


int par3_list(PAR3_CTX *par3_ctx)
{
	int ret;

	ret = read_vital_packet(par3_ctx);
	if (ret != 0)
		return ret;

	ret = parse_vital_packet(par3_ctx);
	if (ret != 0)
		return ret;

	// Show archived file data.
	if (par3_ctx->noise_level >= 0)
		show_data_size(par3_ctx);
	if (par3_ctx->noise_level == -1){
		show_read_result(par3_ctx, 0);
	} else if (par3_ctx->noise_level == 0){
		show_read_result(par3_ctx, 1);
	} else if (par3_ctx->noise_level >= 1){
		show_read_result(par3_ctx, 2);
	}

	return 0;
}

int par3_verify(PAR3_CTX *par3_ctx)
{
	int ret;
	uint32_t missing_dir_count, missing_file_count;
	uint32_t misnamed_file_count, damaged_file_count;
	uint64_t block_count, block_available, recovery_block_available;

	ret = read_vital_packet(par3_ctx);
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
	block_count = par3_ctx->block_count;
	if (block_count > 0){
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

	// Check input file and directory.
	missing_dir_count = check_input_directory(par3_ctx);
	missing_file_count = 0;
	damaged_file_count = 0;
	misnamed_file_count = 0;
	ret = verify_input_file(par3_ctx, &missing_file_count, &damaged_file_count);
	if (ret != 0)
		return ret;

	if (missing_file_count + damaged_file_count > 0){
		// Data Packets substitute for lost input blocks.
		ret = substitute_input_block(par3_ctx);
		if (ret != 0)
			return ret;

		// Find identical input blocks
		ret = find_identical_block(par3_ctx);
		if (ret != 0)
			return ret;

		// Aggregate verified result of available input blocks
		block_available = aggregate_input_block(par3_ctx);

		// When blocks are not enough, check extra files next.
		if (block_available < block_count){
			// Check extra files and misnamed files.
			ret = verify_extra_file(par3_ctx, &missing_file_count, &damaged_file_count, &misnamed_file_count);
			if (ret != 0)
				return ret;

			// Aggregate again
			block_available = aggregate_input_block(par3_ctx);
		}
	}

	if (missing_dir_count + missing_file_count + damaged_file_count + misnamed_file_count > 0){
		if (par3_ctx->noise_level >= -1){
			printf("\nRepair is required.\n");
		}
		if (par3_ctx->noise_level >= 0){
			if (missing_dir_count > 0){
				printf("%u directories are missing.\n", missing_dir_count);
			}
			if (par3_ctx->input_dir_count - missing_dir_count > 0){
				printf("%u directories are ok.\n", par3_ctx->input_dir_count - missing_dir_count);
			}
			if (misnamed_file_count > 0){
				printf("%u files have the wrong name.\n", misnamed_file_count);
			}
			if (missing_file_count > 0){
				printf("%u files are missing.\n", missing_file_count);
			}
			if (damaged_file_count > 0){
				printf("%u files exist but are damaged.\n", damaged_file_count);
			}
			if (par3_ctx->input_file_count - missing_file_count - damaged_file_count - misnamed_file_count > 0){
				printf("%u files are ok.\n", par3_ctx->input_file_count - missing_file_count - damaged_file_count - misnamed_file_count);
			}
			if (missing_file_count + damaged_file_count > 0){
				printf("You have %"PRINT64"u out of %"PRINT64"u input blocks available.\n", block_available, block_count);
			}
		}

		// Aggregate recovery blocks of each Matrix Packet
		recovery_block_available = aggregate_recovery_block(par3_ctx);
		if (block_available + recovery_block_available >= block_count){
			if (par3_ctx->noise_level >= -1){
				printf("Repair is possible.\n");
			}
			if (par3_ctx->noise_level >= 0){
				if (block_available >= block_count){	// Found enough input blocks.
					printf("None of the recovery blocks will be used for the repair.\n");
				} else {
					if (block_available + recovery_block_available > block_count){
						printf("You have an excess of %"PRINT64"u recovery blocks.\n", block_available + recovery_block_available - block_count);
					}
					printf("%"PRINT64"u recovery blocks will be used to repair.\n", block_count - block_available);
				}
			}
			return RET_REPAIR_POSSIBLE;

		} else {	// Need more blocks to repair.
			if (par3_ctx->noise_level >= -1){
				printf("Repair is not possible.\n");
				printf("You need %"PRINT64"u more recovery blocks to be able to repair.\n", block_count - block_available - recovery_block_available);
			}
			return RET_REPAIR_NOT_POSSIBLE;
		}

	} else {	// There is no damaged or missing files.
		if (par3_ctx->noise_level >= -1){
			printf("\n");
			printf("All files are correct, repair is not required.\n");
		}
		return 0;
	}
}

int par3_repair(PAR3_CTX *par3_ctx, char *temp_path)
{
	int ret;
	uint32_t missing_dir_count, missing_file_count;
	uint32_t misnamed_file_count, damaged_file_count;
	uint64_t block_count, block_available, recovery_block_available;

	ret = read_vital_packet(par3_ctx);
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
	block_count = par3_ctx->block_count;
	if (block_count > 0){
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

	// Check input file and directory.
	missing_dir_count = check_input_directory(par3_ctx);
	missing_file_count = 0;
	damaged_file_count = 0;
	misnamed_file_count = 0;
	ret = verify_input_file(par3_ctx, &missing_file_count, &damaged_file_count);
	if (ret != 0)
		return ret;

	if (missing_file_count + damaged_file_count > 0){
		// Data Packets substitute for lost input blocks.
		ret = substitute_input_block(par3_ctx);
		if (ret != 0)
			return ret;

		// Find identical input blocks
		ret = find_identical_block(par3_ctx);
		if (ret != 0)
			return ret;

		// Aggregate verified result of available input blocks
		block_available = aggregate_input_block(par3_ctx);

		// When blocks are not enough, check extra files next.
		if (block_available < block_count){
			// Check extra files and misnamed files.
			ret = verify_extra_file(par3_ctx, &missing_file_count, &damaged_file_count, &misnamed_file_count);
			if (ret != 0)
				return ret;

			// Aggregate again
			block_available = aggregate_input_block(par3_ctx);
		}
	}

	if (missing_dir_count + missing_file_count + damaged_file_count + misnamed_file_count > 0){
		if (par3_ctx->noise_level >= -1){
			printf("\nRepair is required.\n");
		}
		if (par3_ctx->noise_level >= 0){
			if (missing_dir_count > 0){
				printf("%u directories are missing.\n", missing_dir_count);
			}
			if (par3_ctx->input_dir_count - missing_dir_count > 0){
				printf("%u directories are ok.\n", par3_ctx->input_dir_count - missing_dir_count);
			}
			if (misnamed_file_count > 0){
				printf("%u files have the wrong name.\n", misnamed_file_count);
			}
			if (missing_file_count > 0){
				printf("%u files are missing.\n", missing_file_count);
			}
			if (damaged_file_count > 0){
				printf("%u files exist but are damaged.\n", damaged_file_count);
			}
			if (par3_ctx->input_file_count - missing_file_count - damaged_file_count - misnamed_file_count > 0){
				printf("%u files are ok.\n", par3_ctx->input_file_count - missing_file_count - damaged_file_count - misnamed_file_count);
			}
			if (missing_file_count + damaged_file_count > 0){
				printf("You have %"PRINT64"u out of %"PRINT64"u input blocks available.\n", block_available, block_count);
			}
		}

		// Aggregate recovery blocks of each Matrix Packet
		recovery_block_available = aggregate_recovery_block(par3_ctx);
		if (block_available + recovery_block_available >= block_count){
			if (par3_ctx->noise_level >= -1){
				printf("Repair is possible.\n");
			}
			if (par3_ctx->noise_level >= 0){
				if (block_available >= block_count){	// Found enough input blocks.
					printf("None of the recovery blocks will be used for the repair.\n");
				} else {
					if (block_available + recovery_block_available > block_count){
						printf("You have an excess of %"PRINT64"u recovery blocks.\n", block_available + recovery_block_available - block_count);
					}
					printf("%"PRINT64"u recovery blocks will be used to repair.\n", block_count - block_available);
				}
			}

		} else {	// Need more blocks to repair.
			if (par3_ctx->noise_level >= -1){
				printf("Repair is not possible.\n");
				printf("You need %"PRINT64"u more recovery blocks to be able to repair.\n", block_count - block_available - recovery_block_available);
			}
			// Even when complete repair is impossible, try to repair as possible as it can.
		}

		// When some directories are missing or different.
		if (missing_dir_count > 0){
			// Reconstruct directory tree
			missing_dir_count = reconstruct_directory_tree(par3_ctx);
			// If all directories become ok, return zero.
		}

		// When input blocks are enough, restore missing and damaged file.
		if (block_available >= block_count){
			// Create temporary files and restore content of input files
			ret = restore_input_file(par3_ctx, temp_path);
			if (ret != 0)
				return ret;




		// When recovery blocks are enough, recover lost input blocks.
		} else if (block_available + recovery_block_available >= block_count){

			// Create temporary files



			// When there are missing files.



			// When there are misnamed files.
			if (misnamed_file_count > 0){
				// Restore misnamed files
			
				// But, original file is damaged, backup it before rename ?
				// Misnamed file may be refered for recovery.
			}
		

		}

		// Verify repaired file and rename to original name
		ret = verify_repaired_file(par3_ctx, temp_path, &missing_file_count, &damaged_file_count, &misnamed_file_count);
		if (ret != 0)
			return ret;

		if (missing_dir_count + missing_file_count + damaged_file_count + misnamed_file_count > 0){
			printf("\nRepair failed.\n");
			return RET_REPAIR_FAILED;

		} else {	// Repaired
			// When it repaired all input set
			printf("\nRepair complete.\n");
			return 0;
		}

	} else {	// There is no damaged or missing files.
		if (par3_ctx->noise_level >= -1){
			printf("\n");
			printf("All files are correct, repair is not required.\n");
		}
		return 0;
	}
}

