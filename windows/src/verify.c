
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// MSVC headers
#include <io.h>

#include "blake3/blake3.h"
#include "libpar3.h"
#include "common.h"
#include "hash.h"
#include "verify.h"


// This will check permission and attributes in future.
// return 0 = exist, 1 = missing
// 0x8000 = not directory
// 0x****0000 = permission or attribute is different ?
static int check_directory(char *path)
{
	// MSVC
	struct _finddatai64_t c_file;
	intptr_t handle;

	handle = _findfirst64(path, &c_file);
	if (handle == -1)
		return 1;
	_findclose(handle);

	if ((c_file.attrib & _A_SUBDIR) == 0)
		return 0x8000;

	return 0;
}

// Check existense of each input directory.
int check_input_directory(PAR3_CTX *par3_ctx, uint32_t *missing_dir_count)
{
	int ret;
	uint32_t num;
	PAR3_DIR_CTX *dir_p;

	if (par3_ctx->input_dir_count == 0)
		return 0;

	if (par3_ctx->noise_level >= -1){
		printf("\nVerifying input directories:\n\n");
	}

	num = par3_ctx->input_dir_count;
	dir_p = par3_ctx->input_dir_list;
	while (num > 0){
		if (par3_ctx->noise_level >= -1){
			printf("Target: \"%s\"", dir_p->name);
		}
		ret = check_directory(dir_p->name);
		if (ret == 0){
			if (par3_ctx->noise_level >= -1){
				printf(" - found.\n");
			}
		} else if (ret == 1){
			*missing_dir_count += 1;
			if (par3_ctx->noise_level >= -1){
				printf(" - missing.\n");
			}
		} else if (ret == 0x8000){
			if (par3_ctx->noise_level >= -1){
				printf(" - not directory.\n");
			}
		} else {
			if (par3_ctx->noise_level >= -1){
				printf(" - unknown.\n");
			}
		}

		dir_p++;
		num--;
	}

	return 0;
}

// This will check permission and attributes in future.
// return 0 = exist, 1 = missing
// 0x8000 = not file
// 0x****0000 = permission or attribute is different ?
static int check_file(char *path, uint64_t *current_size)
{
	// MSVC
	struct _finddatai64_t c_file;
	intptr_t handle;

	handle = _findfirst64(path, &c_file);
	if (handle == -1)
		return 1;
	_findclose(handle);

	// Get size of existing file.
	*current_size = c_file.size;	// This may be different from original size.

	if ((c_file.attrib & _A_SUBDIR) == 1)
		return 0x8000;

	return 0;
}

// Check existense and content of each input file.
int verify_input_file(PAR3_CTX *par3_ctx, uint32_t *missing_file_count, uint32_t *damaged_file_count)
{
	int ret;
	uint32_t num;
	uint64_t current_size, file_offset, find_slice, file_damage;
	PAR3_FILE_CTX *file_p;

	if (par3_ctx->input_file_count == 0)
		return 0;

	// Remove input files from extra files
	if (par3_ctx->extra_file_name_len > 0){
		char *list_name;
		size_t len, off, list_len;

		list_name = par3_ctx->extra_file_name;
		list_len = par3_ctx->extra_file_name_len;
		off = 0;
		while (off < list_len){
			//printf("extra file = \"%s\"\n", list_name + off);
			len = strlen(list_name + off);

			// check name in list, and ignore if exist
			if (namez_search(par3_ctx->input_file_name, par3_ctx->input_file_name_len, list_name + off) != NULL){
				//printf("extra file = \"%s\" is an input file.\n", list_name + off);

				// remove from list of extra files
				len += 1;	// add the last null string
				memmove(list_name + off, list_name + off + len, list_len - off - len);
				list_len -= len;

			} else {	// goto next filename
				off += len + 1;
			}
		}
		par3_ctx->extra_file_name_len = list_len;

		if (list_len == 0){	// When all extra files were par files
			free(par3_ctx->extra_file_name);
			par3_ctx->extra_file_name = NULL;
			par3_ctx->extra_file_name_max = 0;
		}

		// Decrease memory for extra files.
		if (par3_ctx->extra_file_name_len < par3_ctx->extra_file_name_max){
			//printf("extra_file_name_len = %zu, extra_file_name_max = %zu\n", par3_ctx->extra_file_name_len, par3_ctx->extra_file_name_max);
			list_name = realloc(par3_ctx->extra_file_name, par3_ctx->extra_file_name_len);
			if (list_name == NULL){
				perror("Failed to allocate memory for extra file");
				return RET_MEMORY_ERROR;
			}
			par3_ctx->extra_file_name = list_name;
			par3_ctx->extra_file_name_max = par3_ctx->extra_file_name_len;
		}
	}

	// Table setup for slide window search
	init_crc_slide_table(par3_ctx, 3);
	ret = crc_list_make(par3_ctx);
	if (ret != 0)
		return ret;
	if (par3_ctx->noise_level >= 2){
		printf("Number of full size blocks = %I64u, chunk tails = %I64u\n", par3_ctx->crc_count, par3_ctx->tail_count);
/*
		// for debug
		for (uint64_t i = 0; i < par3_ctx->crc_count; i++){
			printf("crc_list[%2I64u] = 0x%016I64x , block = %I64u\n", i, par3_ctx->crc_list[i].crc, par3_ctx->crc_list[i].index);
		}
		for (uint64_t i = 0; i < par3_ctx->tail_count; i++){
			printf("tail_list[%2I64u] = 0x%016I64x , slice = %I64u\n", i, par3_ctx->tail_list[i].crc, par3_ctx->tail_list[i].index);
		}
*/
	}

	if (par3_ctx->noise_level >= 0){
		printf("\nVerifying input files:\n\n");
	}

	// Allocate buffer to store file data temporary.
	par3_ctx->work_buf = malloc(par3_ctx->block_size * 2);
	if (par3_ctx->work_buf == NULL){
		perror("Failed to allocate memory for temporary file data");
		return RET_MEMORY_ERROR;
	}

	file_p = par3_ctx->input_file_list;
	for (num = 0; num < par3_ctx->input_file_count; num++){
		ret = check_file(file_p->name, &current_size);
		file_p->state = ret;
		if ( (ret == 0) && ( (file_p->size > 0) || (current_size > 0) ) ){
			file_offset = 0;
			find_slice = 0;

			//printf("Target: \"%s\" - exist (not verified yet).\n", file_p->name);

			if (par3_ctx->noise_level >= 0){
				printf("Opening: \"%s\"\n", file_p->name);
			}
			ret = check_complete_file(par3_ctx, num, current_size, &file_offset);
			//printf("ret = %d, size = %I64u, offset = %I64u\n", ret, current_size, file_offset);
			if (ret > 0)
				return ret;	// error
			if (ret == 0){
				// While file data is complete, file name may be different case on Windows PC.
				// Because Windows OS is case insensitive, I ignore the case, too.
				if (par3_ctx->noise_level >= -1){
					printf("Target: \"%s\" - complete.\n", file_p->name);
				}
			} else {
				file_p->state |= 2;
				*damaged_file_count += 1;

				// Start slide search after the last found block position.
				ret = check_damaged_file(par3_ctx, file_p->name, current_size, file_offset, &file_damage, NULL);
				//printf("ret = %d, size = %I64u, offset = %I64u, damage = %I64u\n",
				//		ret, current_size, file_offset, file_damage);
				if (ret != 0)
					return ret;
				if (par3_ctx->noise_level >= -1){
					printf("Target: \"%s\" - damaged. %I64u of %I64u bytes available.\n",
							file_p->name, current_size - file_damage, current_size);
				}
			}

		} else {
			if (par3_ctx->noise_level >= -1){
				printf("Target: \"%s\"", file_p->name);
			}
			if (ret == 0){
				if (par3_ctx->noise_level >= -1){
					printf(" - found.\n");
				}
			} else if (ret == 1){
				*missing_file_count += 1;
				if (par3_ctx->noise_level >= -1){
					printf(" - missing.\n");
				}
			} else if (ret == 0x8000){
				if (par3_ctx->noise_level >= -1){
					printf(" - not file.\n");
				}
			} else {
				if (par3_ctx->noise_level >= -1){
					printf(" - unknown.\n");
				}
			}
		}

		file_p++;
	}

	return 0;
}

