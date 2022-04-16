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

int par3_verify(PAR3_CTX *par3_ctx, char *temp_path)
{
	int ret;
	uint32_t missing_dir_count, missing_file_count;
	uint32_t misnamed_file_count, damaged_file_count;
	uint64_t block_available;

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

	// Check input file and directory.
	missing_dir_count = 0;
	ret = check_input_directory(par3_ctx, &missing_dir_count);
	if (ret != 0)
		return ret;
	missing_file_count = 0;
	damaged_file_count = 0;
	misnamed_file_count = 0;
	ret = verify_input_file(par3_ctx, &missing_file_count, &damaged_file_count);
	if (ret != 0)
		return ret;

	if (missing_file_count + damaged_file_count > 0){
		// Find identical input blocks
		ret = find_identical_block(par3_ctx);
		if (ret != 0)
			return ret;

		// Aggregate verified result of available input blocks
		block_available = aggregate_input_block(par3_ctx);
	}

/*
When blocks are not enough, check extra files next.
At that time, temp_path may be required ?

*/

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
				printf("You have %I64u out of %I64u input blocks available.\n", block_available, par3_ctx->block_count);
			}
		}

	} else {
		if (par3_ctx->noise_level >= -1){
			printf("\n");
			printf("All files are correct, repair is not required.\n");
		}
	}

/*
{
	FILE *fp;
	fp = fopen("debug_file.txt", "wb");
	if (fp != NULL){
	
		fwrite(par3_ctx->par_file_name, 1, par3_ctx->par_file_name_len, fp);
	
		fclose(fp);
	}
}
*/


	return 0;
}

