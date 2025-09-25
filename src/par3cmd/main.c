#include "../platform/platform.h"

#include "locale_helpers.h"

#include "../libpar3/libpar3.h"
#include "../libpar3/common.h"

#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



// This application name and version
#define PACKAGE "par3cmdline"
#define VERSION "0.0.1"

static void print_version(int show_copyright)
{
	printf(PACKAGE " version " VERSION "\n");

	if (show_copyright){
		printf(
"\nCopyright (C) 2025 Yutaka Sawada.\n\n"
"par3cmdline comes with ABSOLUTELY NO WARRANTY.\n\n"
"This is free software; you can redistribute it and/or modify it\n"
"under the terms of the GNU Lesser General Public License as published\n"
"by the Free Software Foundation; either version 2.1 of the License,\n"
"or (at your option) any later version.\n"
		);
	}
}

static void print_help(void)
{
	printf(
"Usage:\n"
"  par3 -h  : Show this help\n"
"  par3 -V  : Show version\n"
"  par3 -VV : Show version and copyright\n\n"
"  par3 tc       [options] <PAR3 file> [files] : Try to create PAR3 files\n"
"  par3 te       [options] <PAR3 file> [file]  : Try to extend PAR3 files\n"
"  par3 c(reate) [options] <PAR3 file> [files] : Create PAR3 files\n"
"  par3 e(xtend) [options] <PAR3 file> [file]  : Extend PAR3 files\n"
"  par3 v(erify) [options] <PAR3 file> [files] : Verify files using PAR3 file\n"
"  par3 r(epair) [options] <PAR3 file> [files] : Repair files using PAR3 files\n"
"  par3 l(ist)   [options] <PAR3 file>         : List files in PAR3 file\n"
"  par3 ti       [options] <ZIP file>          : Try to insert PAR in ZIP file\n"
"  par3 i(nsert) [options] <ZIP file>          : Insert PAR in ZIP file\n"
"  par3 d(elete) [options] <ZIP file>          : Delete PAR from ZIP file\n"
"  par3 vs       [options] <ZIP file>  [files] : Verify itself\n"
"  par3 rs       [options] <ZIP file>  [files] : Repair itself\n"
"\n"
"Options: (all uses)\n"
"  -B<path> : Set the base-path to use as reference for the datafiles\n"
"  -v [-v]  : Be more verbose\n"
"  -q [-q]  : Be more quiet (-q -q gives silence)\n"
"  -m<n>    : Memory to use\n"
"  --       : Treat all following arguments as filenames\n"
"  -abs     : Enable absolute path\n"
"Options: (verify or repair)\n"
"  -S<n>    : Searching time limit (milli second)\n"
"Options: (create)\n"
"  -b<n>    : Set the Block-Count\n"
"  -s<n>    : Set the Block-Size (don't use both -b and -s)\n"
"  -r<n>    : Level of redundancy (percentage)\n"
"  -rm<n>   : Maximum redundancy (percentage)\n"
"  -c<n>    : Recovery Block-Count (don't use both -r and -c)\n"
"  -cf<n>   : First Recovery-Block-Number\n"
"  -cm<n>   : Maximum Recovery Block-Count\n"
"  -u       : Uniform recovery file sizes\n"
"  -l       : Limit size of recovery files (don't use both -u and -l)\n"
"  -n<n>    : Number of recovery files (don't use both -n and -l)\n"
"  -R       : Recurse into subdirectories\n"
"  -D       : Store Data packets\n"
"  -d<n>    : Enable deduplication of input blocks\n"
"  -e<n>    : Set using Error Correction Codes\n"
"  -i<n>    : Number of interleaving"
"  -fu<n>   : Use UNIX Permissions Packet\n"
"  -ff      : Use FAT Permissions Packet\n"
"  -lp<n>   : Limit repetition of packets in each file\n"
"  -C<text> : Set comment\n"
	);
}

int main(int argc, char *argv[])
{
	char **utf8_argv = NULL, *utf8_argv_buf = NULL;
	char *tmp_p, file_name[_MAX_PATH];
	int argi, ret;
	size_t len;
	PAR3_CTX *par3_ctx = NULL;

	// command-line options
	char command_operation = 0;
	char command_trial = 0;
	char command_option = 0;

	// For non UTF-8 code page system
	ret = 1;
	tmp_p = setlocale(LC_ALL, "");
	if ( (argc > 2) && (tmp_p != NULL) && !ctype_is_utf8() ){
		wchar_t *w_argv_buf;

		//printf("default locale = %s\n", tmp_p);
		len = 0;
		for (argi = 2; argi < argc; argi++){
			//printf("argv[%d] = %s\n", argi, argv[argi]);
			len += strlen(argv[argi]) + 1;
		}
		len++;
		//printf("total length of argv = %zu\n", len);
		utf8_argv_buf = malloc(len * 4 + sizeof(wchar_t) * len * 2);
		utf8_argv = malloc(sizeof(char *) * argc);
		if ( (utf8_argv != NULL) && (utf8_argv_buf != NULL) ){
			w_argv_buf = (wchar_t *)(utf8_argv_buf + len * 4);
			tmp_p = utf8_argv_buf;
			for (argi = 2; argi < argc; argi++){
				len = strlen(argv[argi]);
				memcpy(tmp_p, argv[argi], len);
				tmp_p += len;
				tmp_p[0] = '\n';
				tmp_p++;
			}
			tmp_p[0] = 0;
			tmp_p++;
			len = tmp_p - utf8_argv_buf;
			//printf("total length of argv = %zu\n", len);
			//printf("total argv =\n%s\n", utf8_argv_buf);
			mbstowcs(w_argv_buf, utf8_argv_buf, len);

			// change to UTF-8
			if ( ctype_set_utf8() != 0 ){	// could not change locale
				printf("Failed to set UTF-8.\nUnicode filename won't be supported.\n");
				free(utf8_argv);
				utf8_argv = NULL;
				free(utf8_argv_buf);
				utf8_argv_buf = NULL;
			} else{	// convert each argv to UTF-8 text.
				wcstombs(utf8_argv_buf, w_argv_buf, len * 4);

				utf8_argv[0] = argv[0];
				utf8_argv[1] = argv[1];
				tmp_p = utf8_argv_buf;
				for (argi = 2; argi < argc; argi++){
					utf8_argv[argi] = tmp_p;
					tmp_p = strchr(tmp_p, '\n');
					tmp_p[0] = 0;
					tmp_p++;
					//printf("utf8_argv[%d] = %s\n", argi, utf8_argv[argi]);
				}
			}
			ret = 0;
		}
	}

	if (ret && ctype_set_utf8() != 0){	// change locale's code page to use UTF-8
		printf("Failed to set UTF-8.\nUnicode filename won't be supported.\n");
	}

	// After here, use "ret = *" and "goto prepare_return;" to release memory before return.

	if (argc < 3){
		if (argc == 2){
			if (strcmp(argv[1], "-h") == 0){
				print_help();
				ret = 0;
				goto prepare_return;
			} else if (strcmp(argv[1], "-V") == 0){
				print_version(0);
				ret = 0;
				goto prepare_return;
			} else if (strcmp(argv[1], "-VV") == 0){
				print_version(1);
				ret = 0;
				goto prepare_return;
			}
		}
		printf("Not enough command line arguments.\n");
		printf("To show help, type: par3 -h\n");
		ret = RET_INVALID_COMMAND;
		goto prepare_return;
	}

	// check command
	if ( (strcmp(argv[1], "c") == 0) || (strcmp(argv[1], "create") == 0) ){
		command_operation = 'c';	// create
	} else if ( (strcmp(argv[1], "v") == 0) || (strcmp(argv[1], "verify") == 0) ){
		command_operation = 'v';	// verify
	} else if ( (strcmp(argv[1], "r") == 0) || (strcmp(argv[1], "repair") == 0) ){
		command_operation = 'r';	// repair
	} else if ( (strcmp(argv[1], "l") == 0) || (strcmp(argv[1], "list") == 0) ){
		command_operation = 'l';	// list
	} else if ( (strcmp(argv[1], "e") == 0) || (strcmp(argv[1], "extend") == 0) ){
		command_operation = 'e';	// extend

	} else if (strcmp(argv[1], "tc") == 0){
		command_operation = 'c';	// try to create
		command_trial = 't';
	} else if (strcmp(argv[1], "te") == 0){
		command_operation = 'e';	// try to extend
		command_trial = 't';

	} else if ( (strcmp(argv[1], "i") == 0) || (strcmp(argv[1], "insert") == 0) ){
		command_operation = 'i';	// insert PAR in ZIP
	} else if (strcmp(argv[1], "ti") == 0){
		command_operation = 'i';	// try to insert PAR ito ZIP
		command_trial = 't';
	} else if ( (strcmp(argv[1], "d") == 0) || (strcmp(argv[1], "delete") == 0) ){
		command_operation = 'd';	// delete PAR from ZIP

	} else if (strcmp(argv[1], "vs") == 0){
		command_operation = 'v';	// verify itself
		command_option = 's';
	} else if (strcmp(argv[1], "rs") == 0){
		command_operation = 'r';	// repair itself
		command_option = 's';

	} else {
		print_help();
		ret = RET_INVALID_COMMAND;
		goto prepare_return;
	}

	// Init context.
	par3_ctx = malloc(sizeof(PAR3_CTX));
	if (par3_ctx == NULL){
		perror("Failed to allocate memory\n");
		ret = RET_MEMORY_ERROR;
		goto prepare_return;
	}
	memset(par3_ctx, 0, sizeof(PAR3_CTX));

	if ( (command_operation == 'c') || (command_operation == 'i') ){
		// add text in Creator Packet
		ret = add_creator_text(par3_ctx, PACKAGE " version " VERSION
					"\n(https://github.com/Parchive/par3cmdline)\n");
		if (ret != 0){
			ret = RET_MEMORY_ERROR;
			goto prepare_return;
		}
	}

	// read options
	for (argi = 2; argi < argc; argi++){
		if (utf8_argv != NULL){
			tmp_p = utf8_argv[argi];
		} else {
			tmp_p = argv[argi];
		}
		if (tmp_p[0] == '-'){
			tmp_p++;	// skip the first "-" in front of an option
			if (strcmp(tmp_p, "-") == 0){	// End of options
				break;

			} else if (strcmp(tmp_p, "v") == 0){
				par3_ctx->noise_level++;
			} else if (strcmp(tmp_p, "vv") == 0){
				par3_ctx->noise_level += 2;
			} else if (strcmp(tmp_p, "vvv") == 0){
				par3_ctx->noise_level += 3;
			} else if (strcmp(tmp_p, "q") == 0){
				par3_ctx->noise_level--;
			} else if (strcmp(tmp_p, "qq") == 0){
				par3_ctx->noise_level -= 2;

			} else if ( (tmp_p[0] == 'm') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Set the memory limit
				if (par3_ctx->memory_limit > 0){
					printf("Cannot specify memory limit twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					char *end_p;
					// Get the character that stops the scan
					par3_ctx->memory_limit = strtoull(tmp_p + 1, &end_p, 10);
					//printf("end char = %s\n", end_p);
					if ( (_stricmp(end_p, "g") == 0) || (_stricmp(end_p, "gb") == 0) ){
						par3_ctx->memory_limit <<= 30;	// GB
					} else if ( (_stricmp(end_p, "m") == 0) || (_stricmp(end_p, "mb") == 0) ){
						par3_ctx->memory_limit <<= 20;	// MB
					} else if ( (_stricmp(end_p, "k") == 0) || (_stricmp(end_p, "kb") == 0) ){
						par3_ctx->memory_limit <<= 10;	// KB
					}
				}

			} else if ( (tmp_p[0] == 'S') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Set searching time limit
				if ( (command_operation != 'v') && (command_operation != 'r') ){
					printf("Cannot specify searching time limit unless reparing or verifying.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->search_limit > 0){
					printf("Cannot specify searching time limit twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->search_limit = strtoul(tmp_p + 1, NULL, 10);
				}

			} else if ( (tmp_p[0] == 'B') && (tmp_p[1] != 0) ){	// Set the base-path manually
				if (command_operation == 'l'){
					printf("Cannot specify base-path for listing.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if ( (command_operation == 'i') || (command_operation == 'd') ){
					printf("Cannot specify base-path for PAR inside.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->base_path[0] != 0){
					printf("Cannot specify base-path twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					path_copy(par3_ctx->base_path, tmp_p + 1, _MAX_DIR - 32);
				}

			} else if ( (tmp_p[0] == 'b') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Set the block count
				if (command_operation != 'c'){
					printf("Cannot specify block count unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->block_count > 0){
					printf("Cannot specify block count twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->block_size > 0){
					printf("Cannot specify both block count and block size.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->block_count = strtoull(tmp_p + 1, NULL, 10);
				}

			} else if ( (tmp_p[0] == 's') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Set the block size
				if (command_operation != 'c'){
					printf("Cannot specify block size unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->block_size > 0){
					printf("Cannot specify block size twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->block_count > 0){
					printf("Cannot specify both block count and block size.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->block_size = strtoull(tmp_p + 1, NULL, 10);
				}

			} else if ( (tmp_p[0] == 'r') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Set the amount of redundancy required
				if ( (command_operation != 'c') && (command_operation != 'e') && (command_operation != 'i') ){
					printf("Cannot specify redundancy unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->redundancy_size > 0){
					printf("Cannot specify redundancy twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->recovery_block_count > 0){
					printf("Cannot specify both redundancy and recovery block count.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->redundancy_size = strtoul(tmp_p + 1, NULL, 10);
					if (par3_ctx->redundancy_size > 250){
						printf("Invalid redundancy option: %u\n", par3_ctx->redundancy_size);
						par3_ctx->redundancy_size = 0;	// reset
					}
/*
					// Store redundancy for "PAR inside"
					if ( (command_operation == 'i') && (par3_ctx->redundancy_size > 0) ){
						if (add_creator_text(par3_ctx, tmp_p - 1) != 0){
							ret = RET_MEMORY_ERROR;
							goto prepare_return;
						}
					}
*/
				}

			} else if ( (tmp_p[0] == 'r') && (tmp_p[1] == 'm') && (tmp_p[2] >= '0') && (tmp_p[2] <= '9') ){	// Specify the Max redundancy
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify max redundancy unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->max_redundancy_size > 0){
					printf("Cannot specify max redundancy twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->max_recovery_block > 0){
					printf("Cannot specify both max redundancy and recovery block count.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->max_redundancy_size = strtoul(tmp_p + 2, NULL, 10);
					if (par3_ctx->max_redundancy_size > 250){
						printf("Invalid max redundancy option: %u\n", par3_ctx->max_redundancy_size);
						par3_ctx->max_redundancy_size = 0;	// reset
					}
				}

			} else if ( (tmp_p[0] == 'c') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Set the number of recovery blocks to create
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify recovery block count unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->recovery_block_count > 0){
					printf("Cannot specify recovery block count twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->redundancy_size > 0){
					printf("Cannot specify both recovery block count and redundancy.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->recovery_block_count = strtoull(tmp_p + 1, NULL, 10);
				}

			/*
			This feature may require another command like append or extra.
			It needs a parent PAR3 file instead of input files.
			It needs to verify before creating recovery blocks.
			*/
			} else if ( (tmp_p[0] == 'c') && (tmp_p[1] == 'f') && (tmp_p[2] >= '0') && (tmp_p[2] <= '9') ){	// Specify the First recovery block number
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify first block number unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->first_recovery_block > 0){
					printf("Cannot specify first block twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->first_recovery_block = strtoull(tmp_p + 2, NULL, 10);
/*
					if (par3_ctx->first_recovery_block > 0){
						if (add_creator_text(par3_ctx, tmp_p - 1) != 0){
							ret = RET_MEMORY_ERROR;
							goto prepare_return;
						}
					}
*/
				}

			} else if ( (tmp_p[0] == 'c') && (tmp_p[1] == 'm') && (tmp_p[2] >= '0') && (tmp_p[2] <= '9') ){	// Specify the Max recovery block count
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify max recovery block count unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->max_recovery_block > 0){
					printf("Cannot specify max recovery block count twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->max_recovery_block = strtoull(tmp_p + 2, NULL, 10);
				}

			} else if (strcmp(tmp_p, "u") == 0){	// Specify uniformly sized recovery files
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify uniform files unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->recovery_file_scheme != 0){
					printf("Cannot specify two recovery file size schemes.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->recovery_file_scheme = -1;
/*
					if (add_creator_text(par3_ctx, tmp_p - 1) != 0){
						ret = RET_MEMORY_ERROR;
						goto prepare_return;
					}
*/
				}

			} else if ( (tmp_p[0] == 'l') && ( (tmp_p[1] == 0) || ( (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ) ) ){	// Limit the size of the recovery files
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify limit files unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->recovery_file_scheme != 0){
					printf("Cannot specify two recovery file size schemes.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->recovery_file_count > 0){
					printf("Cannot specify limited size and number of files at the same time.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					if (tmp_p[1] == 0){
						par3_ctx->recovery_file_scheme = -2;
					} else {
						par3_ctx->recovery_file_scheme = strtoll(tmp_p + 1, NULL, 10);
					}
				}

			} else if ( (tmp_p[0] == 'n') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Specify the number of recovery files
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify recovery file count unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->recovery_file_count > 0){
					printf("Cannot specify recovery file count twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if ( (par3_ctx->recovery_file_scheme == -2) || (par3_ctx->recovery_file_scheme > 0) ){
					printf("Cannot specify limited size and number of files at the same time.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->recovery_file_count = strtoul(tmp_p + 1, NULL, 10);
				}

			} else if (strcmp(tmp_p, "R") == 0){	// Enable recursive search
				if (command_operation != 'c'){
					printf("Cannot specify Recursive unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					command_option = 'R';
				}

			} else if (strcmp(tmp_p, "D") == 0){	// Store Data packets
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify Data packet unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->data_packet = 'D';
				}

			} else if ( (tmp_p[0] == 'd') && (tmp_p[1] >= '0') && (tmp_p[1] <= '2') ){	// Enable deduplication
				if (command_operation != 'c'){
					printf("Cannot specify deduplication unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->deduplication != 0){
					printf("Cannot specify deduplication twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->deduplication = tmp_p[1];
					if (par3_ctx->deduplication != '0'){
						if (add_creator_text(par3_ctx, tmp_p - 1) != 0){	// Store this option for debug
							ret = RET_MEMORY_ERROR;
							goto prepare_return;
						}
					}
				}

			} else if ( (tmp_p[0] == 'e') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Error Correction Codes
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify Error Correction Codes unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->ecc_method != 0){
					printf("Cannot specify Error Correction Codes twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->ecc_method = strtoul(tmp_p + 1, NULL, 10);
					if (popcount32(par3_ctx->ecc_method) > 1){
						printf("Cannot specify multiple Error Correction Codes.\n");
						par3_ctx->ecc_method = 0;
					}
				}

			} else if ( (tmp_p[0] == 'i') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Interleaving
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify interleaving unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->interleave != 0){
					printf("Cannot specify interleaving twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->interleave = strtoul(tmp_p + 1, NULL, 10);
/*
					if (par3_ctx->interleave != 0){
						if (add_creator_text(par3_ctx, tmp_p - 1) != 0){	// Store this option for debug
							ret = RET_MEMORY_ERROR;
							goto prepare_return;
						}
					}
*/
				}

			} else if ( (tmp_p[0] == 'f') && (tmp_p[1] == 'u')
					&& ( (tmp_p[2] == 0) || ( (tmp_p[2] >= '0') && (tmp_p[2] <= '9') ) ) ){	// UNIX Permissions Packet
				if ((par3_ctx->file_system & 7) != 0){
					printf("Cannot specify UNIX Permissions Packet twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					if (tmp_p[2] == 0){
						ret = 7;	// 1 = mtime, 2 = i_mode, 4 = directory
					} else {
						ret = strtoul(tmp_p + 2, NULL, 10) & 7;
					}
					par3_ctx->file_system |= ret;
					if (command_operation == 'c'){	// Only creating time
						if (add_creator_text(par3_ctx, tmp_p - 1) != 0){	// Store this option for debug
							ret = RET_MEMORY_ERROR;
							goto prepare_return;
						}
					}
				}

			} else if (strcmp(tmp_p, "ff") == 0){	// FAT Permissions Packet
				if ((par3_ctx->file_system & 0x10000) != 0){
					printf("Cannot specify FAT Permissions Packet twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->file_system |= 0x10000;
					if (command_operation == 'c'){	// Only creating time
						if (add_creator_text(par3_ctx, tmp_p - 1) != 0){	// Store this option for debug
							ret = RET_MEMORY_ERROR;
							goto prepare_return;
						}
					}
				}

			} else if ( (tmp_p[0] == 'l') && (tmp_p[1] == 'p')
					&& (tmp_p[2] >= '0') && (tmp_p[2] <= '9') ){	// Max repetition
				if ( (command_operation != 'c') && (command_operation != 'e') ){
					printf("Cannot specify max repetition unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else if (par3_ctx->repetition_limit != 0){
					printf("Cannot specify max repetition twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					par3_ctx->repetition_limit = strtoul(tmp_p + 2, NULL, 10);
				}

			} else if ( (tmp_p[0] == 'C') && (tmp_p[1] != 0) ){	// Set comment
				if (command_operation != 'c'){
					printf("Cannot specify comment unless creating.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				}
				if (add_comment_text(par3_ctx, tmp_p + 1) != 0){
					ret = RET_MEMORY_ERROR;
					goto prepare_return;
				}

			} else if ( (strcmp(tmp_p, "abs") == 0) || (strcmp(tmp_p, "ABS") == 0) ){	// Enable absolute path
				if (par3_ctx->absolute_path != 0){
					printf("Cannot enable absolute path twice.\n");
					ret = RET_INVALID_COMMAND;
					goto prepare_return;
				} else {
					if (tmp_p[0] == 'A'){
						par3_ctx->absolute_path = 'A';
					} else {
						par3_ctx->absolute_path = 'a';
					}
				}

			} else {
				printf("Invalid option specified: %s\n", tmp_p - 1);
				ret = RET_INVALID_COMMAND;
				goto prepare_return;
			}

		} else {
			break;
		}
	}

	if (par3_ctx->creator_packet_size > 0){
		// Erase return code at the end of Creator text
		par3_ctx->creator_packet_size = trim_text(par3_ctx->creator_packet, par3_ctx->creator_packet_size);
	}
	if (par3_ctx->comment_packet_size > 0){
		// Erase return code at the end of Comment text
		par3_ctx->comment_packet_size = trim_text(par3_ctx->comment_packet, par3_ctx->comment_packet_size);
	}

	// read PAR filename
	if (argi < argc){
		if (utf8_argv != NULL){
			tmp_p = utf8_argv[argi];
		} else {
			tmp_p = argv[argi];
		}
		argi++;

		// PAR filename must not include wildcard (* or ?).
		len = strcspn(tmp_p, "*?");
		if (len < strlen(tmp_p)){
			printf("Found wildcard in PAR filename, %s\n", tmp_p);
			par3_ctx->par_filename[0] = 0;
		} else {
			// may add ".vol32768+32768.par3"
			if (path_copy(par3_ctx->par_filename, tmp_p, _MAX_PATH - 20) == 0){
				par3_ctx->par_filename[0] = 0;
			} else {
				ret = get_absolute_path(file_name, par3_ctx->par_filename, _MAX_PATH - 8);
				if (ret != 0){
					printf("Failed to convert PAR filename to absolute path\n");
					ret = RET_FILE_IO_ERROR;
					goto prepare_return;
				}
				// PAR filename may be an absolute path.
				if (_stricmp(file_name, par3_ctx->par_filename) == 0){
					// If base-path is empty, set parent of PAR file.
					if (par3_ctx->base_path[0] == 0){
						tmp_p = strrchr(file_name, '/');
						if (tmp_p != NULL)
							memcpy(par3_ctx->base_path, file_name, tmp_p - file_name);
					}
				// PAR filename may be a relative path from current working directory.
				} else if (par3_ctx->base_path[0] != 0){
					// If base-path isn't empty, it was relative from current working directory.
					strcpy(par3_ctx->par_filename, file_name);
				}
			}
		}
	}
	if (par3_ctx->par_filename[0] == 0){
		printf("PAR filename is not specified\n");
		ret = RET_INVALID_COMMAND;
		goto prepare_return;
	} else if ( (command_operation == 'i') || (command_operation == 'd') || (command_option == 's') ){
		// It removes sub-directory from PAR filename when using "PAR inside" feature.
		tmp_p = offset_file_name(par3_ctx->par_filename);
		if (tmp_p > par3_ctx->par_filename){
			strcpy(file_name, tmp_p);
			tmp_p[-1] = 0;
			strcpy(par3_ctx->base_path, par3_ctx->par_filename);
			strcpy(par3_ctx->par_filename, file_name);
		} else {
			par3_ctx->base_path[0] = 0;	// clear base-path
		}
		if (command_option == 's'){	// Check file extension for "PAR inside ZIP"
			tmp_p = par3_ctx->par_filename;
			len = strlen(tmp_p);
			if ( (_stricmp(tmp_p + len - 4, ".zip") != 0) && (_stricmp(tmp_p + len - 3, ".7z") != 0) ){
				printf("File extension is different from ZIP.\n");
				ret = RET_FILE_IO_ERROR;
				goto prepare_return;
			}
		}
	} else {
		tmp_p = par3_ctx->par_filename;
		len = strlen(tmp_p);
		// add standard extension
		if (_stricmp(tmp_p + len - 5, ".par3") != 0){
			strcat(tmp_p, ".par3");
		}
	}

	if (par3_ctx->base_path[0] != 0){
		if (par3_ctx->absolute_path != 0){	// Convert base-path to absolute path.
			ret = get_absolute_path(file_name, par3_ctx->base_path, _MAX_PATH - 4);
			if (ret != 0){
				printf("Failed to convert base-path to absolute path\n");
				ret = RET_FILE_IO_ERROR;
				goto prepare_return;
			}
			strcpy(par3_ctx->base_path, file_name);
		}

		// change current directory to the specified base-path
		if (_chdir(par3_ctx->base_path) != 0){
			perror("Failed to change working directory");
			ret = RET_FILE_IO_ERROR;
			goto prepare_return;
		}
	} else if ( (command_operation == 'c') && (par3_ctx->absolute_path != 0) ){
		// If base-path is empty at creation, current working directory becomes the absolute path.
		if (_getcwd(par3_ctx->base_path, _MAX_PATH - 4) == NULL){
			perror("Failed to get current working directory\n");
			ret = RET_FILE_IO_ERROR;
			goto prepare_return;
		}
	}

	if (par3_ctx->noise_level >= 1){
		if (par3_ctx->memory_limit != 0){
			if ((par3_ctx->memory_limit & ((1 << 30) - 1)) == 0){
				printf("memory_limit = %"PRIu64" GB\n", par3_ctx->memory_limit >> 30);
			} else if ((par3_ctx->memory_limit & ((1 << 20) - 1)) == 0){
				printf("memory_limit = %"PRIu64" MB\n", par3_ctx->memory_limit >> 20);
			} else if ((par3_ctx->memory_limit & ((1 << 10) - 1)) == 0){
				printf("memory_limit = %"PRIu64" KB\n", par3_ctx->memory_limit >> 10);
			} else {
				printf("memory_limit = %"PRIu64" Bytes\n", par3_ctx->memory_limit);
			}
		}
		if (par3_ctx->search_limit != 0)
			printf("search_limit = %d ms\n", par3_ctx->search_limit);
		if (par3_ctx->block_count != 0)
			printf("Specified block count = %"PRIu64"\n", par3_ctx->block_count);
		if (par3_ctx->block_size != 0)
			printf("Specified block size = %"PRIu64"\n", par3_ctx->block_size);
		if (par3_ctx->redundancy_size != 0)
			printf("Specified redundancy = %u %%\n", par3_ctx->redundancy_size);
		if (par3_ctx->max_redundancy_size != 0)
			printf("max_redundancy_size = %u\n", par3_ctx->max_redundancy_size);
		if (par3_ctx->recovery_block_count != 0)
			printf("recovery_block_count = %"PRIu64"\n", par3_ctx->recovery_block_count);
		if (par3_ctx->first_recovery_block != 0)
			printf("First recovery block number = %"PRIu64"\n", par3_ctx->first_recovery_block);
		if (par3_ctx->max_recovery_block != 0)
			printf("max_recovery_block = %"PRIu64"\n", par3_ctx->max_recovery_block);
		if (par3_ctx->recovery_file_count != 0)
			printf("Specified number of recovery files = %u\n", par3_ctx->recovery_file_count);
		if (par3_ctx->recovery_file_scheme != 0){
			if (par3_ctx->recovery_file_scheme == -1){
				printf("Recovery file sizing = uniform\n");
			} else if (par3_ctx->recovery_file_scheme == -2){
				printf("Recovery file sizing = limit\n");
			} else if (par3_ctx->recovery_file_scheme > 0){
				printf("Recovery file sizing = limit to %"PRId64"\n", par3_ctx->recovery_file_scheme);
			}
		}
		if (par3_ctx->ecc_method != 0)
			printf("Error Correction Codes = %u\n", par3_ctx->ecc_method);
		if (par3_ctx->interleave != 0){
			if (par3_ctx->ecc_method == 8){	// FFT based Reed-Solomon Codes
				printf("Specified interleaving times = %u\n", par3_ctx->interleave);
			} else {	// Disabled at other Error Correction Codes.
				par3_ctx->interleave = 0;
			}
		}
		if (par3_ctx->file_system != 0)
			printf("File System Packet = 0x%X\n", par3_ctx->file_system);
		if (par3_ctx->deduplication != 0)
			printf("deduplication = level %c\n", par3_ctx->deduplication);
		if (command_option == 'R')
			printf("recursive search = enable\n");
		if (par3_ctx->absolute_path != 0)
			printf("Absolute path = enable\n");
		if (par3_ctx->data_packet != 0)
			printf("Data packet = store\n");
		if (par3_ctx->repetition_limit != 0)
			printf("Max packet repetition = %u\n", par3_ctx->repetition_limit);
		if (par3_ctx->base_path[0] != 0)
			printf("Base path = \"%s\"\n", par3_ctx->base_path);
		printf("PAR file = \"%s\"\n", par3_ctx->par_filename);
		printf("\n");
	}

	if (command_operation == 'c'){	// Create

		// When there is no argument for input file, return to the PAR file name.
		if (argi == argc)
			argi--;

		// search input files
		for (; argi < argc; argi++){
			if (utf8_argv != NULL){
				tmp_p = utf8_argv[argi];
			} else {
				tmp_p = argv[argi];
			}

			// read path of an input file
			path_copy(file_name, tmp_p, _MAX_FNAME - 32);
			if (file_name[0] == 0)
				continue;
			//if (par3_ctx->noise_level >= 2){
			//	printf("argv[%d] = \"%s\"\n", argi, file_name);
			//}

			// search files by wild card matching
			ret = path_search(par3_ctx, file_name, command_option);
			if (ret != 0){
				printf("Failed to search: %s\n", file_name);
				goto prepare_return;
			}
		}

		// release UTF-8 argv
		if (utf8_argv != NULL){
			free(utf8_argv);
			utf8_argv = NULL;
		}
		if (utf8_argv_buf != NULL){
			free(utf8_argv_buf);
			utf8_argv_buf = NULL;
		}

		// Count number of found input files and directories.
		par3_ctx->input_file_count = namez_count(par3_ctx->input_file_name, par3_ctx->input_file_name_len);
		par3_ctx->input_dir_count = namez_count(par3_ctx->input_dir_name, par3_ctx->input_dir_name_len);
		if (par3_ctx->input_file_count + par3_ctx->input_dir_count == 0){
			printf("You must specify a list of files when creating.\n");
			ret = RET_INVALID_COMMAND;
			goto prepare_return;
		}
		if (par3_ctx->noise_level >= 0){
			printf("Number of input file = %u, directory = %u\n", par3_ctx->input_file_count, par3_ctx->input_dir_count);
		}

		// get information of input files
		ret = get_file_status(par3_ctx);
		if (ret != 0){
			printf("Failed to check file status\n");
			goto prepare_return;
		}
		if (par3_ctx->block_count > 0){
			// It's difficult to predict arrangement of blocks.
			// Calculate "Block size" from "Total data size" dividing "Block count" simply.
			// The result may be different from the specified block count.
			par3_ctx->block_size = (par3_ctx->total_file_size + par3_ctx->block_count - 1) / par3_ctx->block_count;
			// Block size must be multiple of 2 for 16-bit Reed-Solomon Codes.
			if (par3_ctx->block_size & 1)
				par3_ctx->block_size += 1;
			if (par3_ctx->noise_level >= 0){
				printf("Suggested block size = %"PRIu64"\n", par3_ctx->block_size);
			}
		} else if (par3_ctx->block_size == 0){
			par3_ctx->block_size = suggest_block_size(par3_ctx);
			if (par3_ctx->noise_level >= 0){
				printf("Suggested block size = %"PRIu64"\n", par3_ctx->block_size);
			}
		} else if (par3_ctx->block_size & 1){
			// Always increasing to multiple of 2 is easier ?
			//if ( (par3_ctx->recovery_block_count > 128) || (par3_ctx->max_recovery_block > 128)
			//		|| (calculate_block_count(par3_ctx, par3_ctx->block_size) > 128) ){
				// Block size must be multiple of 2 for 16-bit Reed-Solomon Codes.
				par3_ctx->block_size += 1;
				if (par3_ctx->noise_level >= 0){
					printf("Suggested block size = %"PRIu64"\n", par3_ctx->block_size);
				}
			//}
		}
		par3_ctx->block_count = calculate_block_count(par3_ctx, par3_ctx->block_size);
		if (par3_ctx->noise_level >= 0){
			printf("Possible block count = %"PRIu64"\n", par3_ctx->block_count);
			printf("\n");
		}

		// sort input files for efficient tail packing.
		ret = sort_input_set(par3_ctx);
		if (ret != 0){
			printf("Failed to sort input sets\n");
			goto prepare_return;
		}

		if (command_trial == 0){
			// create recovery files
			ret = par3_create(par3_ctx, file_name);
		} else {
			// try to create recovery files
			ret = par3_trial(par3_ctx, file_name);
		}
		if (ret != 0){
			printf("Failed to create PAR file\n");
			goto prepare_return;
		}
		if (par3_ctx->noise_level >= -1)
			printf("Done\n");

	} else if ( (command_operation == 'v') || (command_operation == 'r') || (command_operation == 'l') ){	// Verify, Repair or List

		if (command_operation != 'l'){	// Verify or Repair
			// search extra files
			for (; argi < argc; argi++){
				if (utf8_argv != NULL){
					tmp_p = utf8_argv[argi];
				} else {
					tmp_p = argv[argi];
				}

				// read relative path of an input file
				path_copy(file_name, tmp_p, _MAX_FNAME - 32);
				if (file_name[0] == 0)
					continue;
				//if (par3_ctx->noise_level >= 2){
				//	printf("argv[%d] = \"%s\"\n", argi, file_name);
				//}

				// search files by wild card matching
				ret = extra_search(par3_ctx, file_name);
				if (ret != 0){
					printf("Failed to search: %s\n", file_name);
					goto prepare_return;
				}
			}
		}

		// release UTF-8 argv
		if (utf8_argv != NULL){
			free(utf8_argv);
			utf8_argv = NULL;
		}
		if (utf8_argv_buf != NULL){
			free(utf8_argv_buf);
			utf8_argv_buf = NULL;
		}

		// search par files
		if ( (command_operation == 'l') || (command_option == 's') ){	// List or Self
			ret = par_search(par3_ctx, par3_ctx->par_filename, 0);	// Check the specified PAR3 file only.
		} else {	// Verify or Repair
			ret = par_search(par3_ctx, par3_ctx->par_filename, 1);	// Check other PAR3 files, too.
		}
		if (ret != 0){
			printf("Failed to search PAR files\n");
			goto prepare_return;
		}

		if (command_operation == 'l'){
			ret = par3_list(par3_ctx);
			if (ret != 0){
				printf("Failed to list files in PAR file\n");
				goto prepare_return;
			}
			if (par3_ctx->noise_level >= -1)
				printf("Listed\n");

		} else if (command_operation == 'v'){
			ret = par3_verify(par3_ctx);
			if ( (ret != 0) && (ret != RET_REPAIR_POSSIBLE) && (ret != RET_REPAIR_NOT_POSSIBLE) ){
				printf("Failed to verify with PAR file\n");
				goto prepare_return;
			}

		} else {
			ret = par3_repair(par3_ctx, file_name);
			if ( (ret != 0) && (ret != RET_REPAIR_FAILED) && (ret != RET_REPAIR_NOT_POSSIBLE) ){
				printf("Failed to repair with PAR file\n");
				goto prepare_return;
			}
		}

	} else if (command_operation == 'e'){	// Extend

		// Base name of reference files is same as creating PAR3 files.
		if (argi == argc){
			if (par3_ctx->noise_level >= 1){
				printf("Reference file = \"%s\"\n", par3_ctx->par_filename);
			}
			ret = par_search(par3_ctx, par3_ctx->par_filename, 1);
			if (ret != 0){
				printf("Failed to search PAR files\n");
				goto prepare_return;
			}

		// search reference files
		} else {
			if (utf8_argv != NULL){
				tmp_p = utf8_argv[argi];
			} else {
				tmp_p = argv[argi];
			}

			// read relative path of a reference file
			path_copy(file_name, tmp_p, _MAX_FNAME - 32);
			if (file_name[0] == 0){
				printf("PAR filename is not specified\n");
				ret = RET_INVALID_COMMAND;
				goto prepare_return;
			}
			// PAR filename must not include wildcard (* or ?).
			len = strcspn(file_name, "*?");
			if (len < strlen(file_name)){
				printf("Found wildcard in PAR filename, %s\n", file_name);
				ret = RET_INVALID_COMMAND;
				goto prepare_return;
			} else {
				// PAR filename may be a relative path from current working directory.
				if (par3_ctx->base_path[0] != 0){
					char absolute_path[_MAX_PATH];
					// if base-path isn't empty, relative from current working directory.
					ret = get_absolute_path(absolute_path, file_name, _MAX_PATH - 8);
					if (ret != 0){
						printf("Failed to convert PAR filename to absolute path\n");
						ret = RET_FILE_IO_ERROR;
						goto prepare_return;
					}
					strcpy(file_name, absolute_path);
				}
			}
			if (par3_ctx->noise_level >= 1){
				printf("Reference file = \"%s\"\n", file_name);
			}

			// search par files
			ret = par_search(par3_ctx, file_name, 1);
			if (ret != 0){
				printf("Failed to search: %s\n", file_name);
				goto prepare_return;
			}
		}

		// release UTF-8 argv
		if (utf8_argv != NULL){
			free(utf8_argv);
			utf8_argv = NULL;
		}
		if (utf8_argv_buf != NULL){
			free(utf8_argv_buf);
			utf8_argv_buf = NULL;
		}

		ret = par3_extend(par3_ctx, command_trial, file_name);
		if (ret != 0){
			printf("Failed to extend PAR file\n");
			goto prepare_return;
		}
		if (par3_ctx->noise_level >= -1)
			printf("Done\n");

	} else if ( (command_operation == 'i') || (command_operation == 'd') ){	// PAR inside

		// Outside file = input file = PAR file
		par3_ctx->input_file_name_len = strlen(par3_ctx->par_filename) + 1;
		par3_ctx->input_file_name_max = par3_ctx->input_file_name_len;
		par3_ctx->input_file_name = malloc(par3_ctx->input_file_name_max);
		if (par3_ctx->input_file_name == NULL){
			ret = RET_MEMORY_ERROR;
			goto prepare_return;
		}
		strcpy(par3_ctx->input_file_name, par3_ctx->par_filename);
		//printf("input file = \"%s\"\n", par3_ctx->input_file_name);
		par3_ctx->input_file_count = 1;

		// release UTF-8 argv
		if (utf8_argv != NULL){
			free(utf8_argv);
			utf8_argv = NULL;
		}
		if (utf8_argv_buf != NULL){
			free(utf8_argv_buf);
			utf8_argv_buf = NULL;
		}

		// get information of input files
		ret = get_file_status(par3_ctx);
		if (ret != 0){
			printf("Failed to check file status\n");
			goto prepare_return;
		}

		if (command_operation == 'i'){
			// insert PAR3 packets in ZIP file
			ret = par3_insert_zip(par3_ctx, command_trial);
		} else if (command_operation == 'd'){
			// delete PAR3 packets from ZIP file
			ret = par3_delete_zip(par3_ctx);
		} else {
			ret = RET_INVALID_COMMAND;
		}
		if (ret != 0){
			printf("Failed to operate PAR inside ZIP\n");
			goto prepare_return;
		}
		if (par3_ctx->noise_level >= -1)
			printf("Done\n");
	}

	ret = 0;
prepare_return:

	// release memory
	if (utf8_argv != NULL)
		free(utf8_argv);
	if (utf8_argv_buf != NULL)
		free(utf8_argv_buf);
	if (par3_ctx != NULL){
		par3_release(par3_ctx);
		free(par3_ctx);
	}

	return ret;
}
