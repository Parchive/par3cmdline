
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

// Check existense and content of each input file.
int verify_input_file(PAR3_CTX *par3_ctx)
{
	int ret;
	uint32_t num;
	PAR3_FILE_CTX *file_p;

	if (par3_ctx->input_file_count == 0)
		return 0;

	printf("\nVerifying input files:\n\n");

	num = par3_ctx->input_file_count;
	file_p = par3_ctx->input_file_list;
	while (num > 0){
		ret = check_file(file_p->name);
		if (ret == 0){

			//printf("Opening: \"%s\"\n", file_p->name);
			printf("Target: \"%s\" - exist (not verified yet).\n", file_p->name);


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
		num--;
	}

	return 0;
}

