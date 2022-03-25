
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
#include "hash.h"


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
int check_input_directory(PAR3_CTX *par3_ctx)
{
	int ret;
	uint32_t num;
	PAR3_DIR_CTX *dir_p;

	if (par3_ctx->input_dir_count == 0)
		return 0;

	printf("\nVerifying input directories:\n\n");

	num = par3_ctx->input_dir_count;
	dir_p = par3_ctx->input_dir_list;
	while (num > 0){
		printf("Target: \"%s\"", dir_p->name);
		ret = check_directory(dir_p->name);
		if (ret == 0){
			printf(" - found.\n");
		} else if (ret == 1){
			printf(" - missing.\n");
		} else if (ret == 0x8000){
			printf(" - not directory.\n");
		} else {
			printf(" - unknown.\n");
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
static int check_file(char *path)
{
	// MSVC
	struct _finddatai64_t c_file;
	intptr_t handle;

	handle = _findfirst64(path, &c_file);
	if (handle == -1)
		return 1;
	_findclose(handle);

	if ((c_file.attrib & _A_SUBDIR) == 1)
		return 0x8000;

	return 0;
}

// This checks chunks in the file.
static int check_chunk_map(PAR3_CTX *par3_ctx, uint32_t file_id)
{
	uint64_t crc_count;
	uint64_t window_mask, *window_table;
	PAR3_FILE_CTX *file_p;
	PAR3_CMP_CTX *crc_list;

	window_mask = par3_ctx->window_mask;
	window_table = par3_ctx->window_table;
	crc_list = par3_ctx->crc_list;
	crc_count = par3_ctx->crc_count;


	file_p = par3_ctx->input_file_list + file_id;

	//printf("file size = %I64u \"%s\"\n", file_p->size, file_p->name);


	return 0;
}

// Check existense and content of each input file.
int verify_input_file(PAR3_CTX *par3_ctx)
{
	int ret;
	uint32_t num;
	PAR3_FILE_CTX *file_p;

	if (par3_ctx->input_file_count == 0)
		return 0;

	printf("\nVerifying input files:\n\n");

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
			printf("crc_list[%2I64u] = 0x%016I64x , %I64u\n", i, par3_ctx->crc_list[i].crc, par3_ctx->crc_list[i].index);
		}
		for (uint64_t i = 0; i < par3_ctx->tail_count; i++){
			printf("tail_list[%2I64u] = 0x%016I64x , %I64u\n", i, par3_ctx->tail_list[i].crc, par3_ctx->tail_list[i].index);
		}
*/
	}

	file_p = par3_ctx->input_file_list;
	for (num = 0; num < par3_ctx->input_file_count; num++){
		ret = check_file(file_p->name);
		if (ret == 0){

			//printf("Opening: \"%s\"\n", file_p->name);
			printf("Target: \"%s\" - exist (not verified yet).\n", file_p->name);

			//ret = check_chunk_map(par3_ctx, num);



		} else {
			printf("Target: \"%s\"", file_p->name);
			if (ret == 1){
				printf(" - missing.\n");
			} else if (ret == 0x8000){
				printf(" - not file.\n");
			} else {
				printf(" - unknown.\n");
			}
		}

		file_p++;
	}

	return 0;
}

