
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// MSVC headers
#include <direct.h>

#include "libpar3.h"
#include "common.h"


// This application name and version
#define PACKAGE "par3cmdline"
#define VERSION "0.0.1"

static void print_version(int show_copyright)
{
	printf(PACKAGE " version " VERSION "\n");

	if (show_copyright){
		printf(
"\nCopyright (C) 2022 Yutaka Sawada.\n\n"
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
"  par3 -h  : show this help\n"
"  par3 -V  : show version\n"
"  par3 -VV : show version and copyright\n\n"
"  par3 t(rial)  [options] <PAR3 file> [files] : Try to create PAR3 files\n"
"  par3 c(reate) [options] <PAR3 file> [files] : Create PAR3 files\n"
"  par3 v(erify) [options] <PAR3 file> [files] : Verify files using PAR3 file\n"
"  par3 r(epair) [options] <PAR3 file> [files] : Repair files using PAR3 files\n"
"  par3 l(ist)   [options] <PAR3 file>         : List files in PAR3 file\n"
"\n"
"Options: (all uses)\n"
"  -B<path> : Set the base-path to use as reference for the datafiles\n"
"  -v [-v]  : Be more verbose\n"
"  -q [-q]  : Be more quiet (-q -q gives silence)\n"
"  -m<n>    : Memory (in MB) to use\n"
"  --       : Treat all following arguments as filenames\n"
"  -abs     : Enable absolute path\n"
"Options: (verify or repair)\n"
"  -S<n>    : Searching time limit (milli second)\n"
"Options: (create)\n"
"  -s<n>    : Set the Block-Size (don't use both -b and -s)\n"
"  -r<n>    : Level of redundancy (%%)\n"
"  -c<n>    : Recovery Block-Count (don't use both -r and -c)\n"
"  -f<n>    : First Recovery-Block-Number\n"
"  -u       : Uniform recovery file sizes\n"
"  -l       : Limit size of recovery files (don't use both -u and -l)\n"
"  -n<n>    : Number of recovery files (don't use both -n and -l)\n"
"  -R       : Recurse into subdirectories\n"
"  -D       : Store Data packets\n"
"  -d<n>    : Enable deduplication of input blocks\n"
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
	char command_operation;
	char command_recursive = 0;

	// For non UTF-8 code page system
	ret = 1;
	tmp_p = setlocale(LC_ALL, "");
	if ( (argc > 2) && (tmp_p != NULL) && (strstr(tmp_p, "utf8") == NULL) ){
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
			if (setlocale(LC_ALL, ".UTF-8") == NULL){	// could not change locale
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

	if (ret){	// change locale's code page to use UTF-8
		tmp_p = setlocale(LC_ALL, ".UTF-8");
		if (tmp_p == NULL){
			printf("Failed to set UTF-8.\nUnicode filename won't be supported.\n");
		}
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
	} else if ( (strcmp(argv[1], "t") == 0) || (strcmp(argv[1], "trial") == 0) ){
		command_operation = 't';	// trial
	} else if ( (strcmp(argv[1], "l") == 0) || (strcmp(argv[1], "list") == 0) ){
		command_operation = 'l';	// list

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

	if ( (command_operation == 'c') || (command_operation == 't') ){
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
			} else if (strcmp(tmp_p, "q") == 0){
				par3_ctx->noise_level--;
			} else if (strcmp(tmp_p, "qq") == 0){
				par3_ctx->noise_level -= 2;

			} else if ( (tmp_p[0] == 'm') && (tmp_p[1] >= '1') && (tmp_p[1] <= '9') ){	// Set the memory limit
				if (par3_ctx->memory_limit > 0){
					printf("Cannot specify memory limit twice.\n");
				} else {
					par3_ctx->memory_limit = strtoull(tmp_p + 1, NULL, 10);
					par3_ctx->memory_limit *= 1048576;	// MB
				}

			} else if ( (tmp_p[0] == 'S') && (tmp_p[1] >= '1') && (tmp_p[1] <= '9') ){	// Set searching time limit
				if ( (command_operation != 'v') && (command_operation != 'r') ){
					printf("Cannot specify searching time limit unless reparing or verifying.\n");
				} else if (par3_ctx->search_limit > 0){
					printf("Cannot specify searching time limit twice.\n");
				} else {
					par3_ctx->search_limit = strtoul(tmp_p + 1, NULL, 10);
				}

			} else if ( (tmp_p[0] == 'B') && (tmp_p[1] != 0) ){	// Set the base-path manually
				path_copy(par3_ctx->base_path, tmp_p + 1, _MAX_DIR - 32);

			} else if ( (tmp_p[0] == 's') && (tmp_p[1] >= '1') && (tmp_p[1] <= '9') ){	// Set the block size
				if ( (command_operation != 'c') && (command_operation != 't') ){
					printf("Cannot specify block size unless creating.\n");
				} else if (par3_ctx->block_size > 0){
					printf("Cannot specify block size twice.\n");
				} else {
					par3_ctx->block_size = strtoull(tmp_p + 1, NULL, 10);
/*
					// This is for debug.
					// No need to save this value, because block size is stored in Start Packet.
					if (par3_ctx->block_size > 0){
						if (add_creator_text(par3_ctx, tmp_p - 1) != 0){
							ret = RET_MEMORY_ERROR;
							goto prepare_return;
						}
					}
*/
				}

			} else if ( (tmp_p[0] == 'r') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Set the amount of redundancy required
				if ( (command_operation != 'c') && (command_operation != 't') ){
					printf("Cannot specify redundancy unless creating.\n");
				} else if (par3_ctx->redundancy_size > 0){
					printf("Cannot specify redundancy twice.\n");
				} else if (par3_ctx->recovery_block_count > 0){
					printf("Cannot specify both redundancy and recovery block count.\n");
				} else {
					par3_ctx->redundancy_size = strtoul(tmp_p + 1, NULL, 10);
					if (par3_ctx->redundancy_size > 250){
						printf("Invalid redundancy option: %u\n", par3_ctx->redundancy_size);
						par3_ctx->redundancy_size = 0;	// reset
					}
				}

			} else if ( (tmp_p[0] == 'c') && (tmp_p[1] >= '1') && (tmp_p[1] <= '9') ){	// Set the number of recovery blocks to create
				if ( (command_operation != 'c') && (command_operation != 't') ){
					printf("Cannot specify recovery block count unless creating.\n");
				} else if (par3_ctx->recovery_block_count > 0){
					printf("Cannot specify recovery block count twice.\n");
				} else if (par3_ctx->redundancy_size > 0){
					printf("Cannot specify both recovery block count and redundancy.\n");
				} else {
					par3_ctx->recovery_block_count = strtoull(tmp_p + 1, NULL, 10);
				}

			/*
			This feature may require another command like append or extra.
			It needs a parent PAR3 file instead of input files.
			It needs to verify before creating recovery blocks.
			*/
			} else if ( (tmp_p[0] == 'f') && (tmp_p[1] >= '0') && (tmp_p[1] <= '9') ){	// Specify the First block recovery number
				if ( (command_operation != 'c') && (command_operation != 't') ){
					printf("Cannot specify first block number unless creating.\n");
				} else if (par3_ctx->first_recovery_block > 0){
					printf("Cannot specify first block twice.\n");
				} else {
					par3_ctx->first_recovery_block = strtoull(tmp_p + 1, NULL, 10);
					if (par3_ctx->first_recovery_block > 0){
						if (add_creator_text(par3_ctx, tmp_p - 1) != 0){
							ret = RET_MEMORY_ERROR;
							goto prepare_return;
						}
					}
				}

			} else if (strcmp(tmp_p, "u") == 0){	// Specify uniformly sized recovery files
				if ( (command_operation != 'c') && (command_operation != 't') ){
					printf("Cannot specify uniform files unless creating.\n");
				} else if (par3_ctx->recovery_file_scheme != 0){
					printf("Cannot specify two recovery file size schemes.\n");
				} else {
					par3_ctx->recovery_file_scheme = 'u';
					if (add_creator_text(par3_ctx, tmp_p - 1) != 0){
						ret = RET_MEMORY_ERROR;
						goto prepare_return;
					}
				}

			} else if (strcmp(tmp_p, "l") == 0){	// Limit the size of the recovery files
				if ( (command_operation != 'c') && (command_operation != 't') ){
					printf("Cannot specify limit files unless creating.\n");
				} else if (par3_ctx->recovery_file_scheme != 0){
					printf("Cannot specify two recovery file size schemes.\n");
				} else if (par3_ctx->recovery_file_count > 0){
					printf("Cannot specify limited size and number of files at the same time.\n");
				} else {
					par3_ctx->recovery_file_scheme = 'l';
					if (add_creator_text(par3_ctx, tmp_p - 1) != 0){
						ret = RET_MEMORY_ERROR;
						goto prepare_return;
					}
				}

			} else if ( (tmp_p[0] == 'n') && (tmp_p[1] >= '1') && (tmp_p[1] <= '9') ){	// Specify the number of recovery files
				if ( (command_operation != 'c') && (command_operation != 't') ){
					printf("Cannot specify recovery file count unless creating.\n");
				} else if (par3_ctx->recovery_file_count > 0){
					printf("Cannot specify recovery file count twice.\n");
				} else if (par3_ctx->recovery_file_scheme == 'l'){
					printf("Cannot specify limited size and number of files at the same time.\n");
				} else {
					par3_ctx->recovery_file_count = strtoul(tmp_p + 1, NULL, 10);
					if (par3_ctx->recovery_file_count > 0){
						if (add_creator_text(par3_ctx, tmp_p - 1) != 0){
							ret = RET_MEMORY_ERROR;
							goto prepare_return;
						}
					}
				}

			} else if (strcmp(tmp_p, "R") == 0){	// Enable recursive search
				if ( (command_operation != 'c') && (command_operation != 't') ){
					printf("Cannot specify Recursive unless creating.\n");
				} else {
					command_recursive = 'R';
				}

			} else if (strcmp(tmp_p, "D") == 0){	// Store Data packets
				if ( (command_operation != 'c') && (command_operation != 't') ){
					printf("Cannot specify Data packet unless creating.\n");
				} else {
					par3_ctx->data_packet = 'D';
				}

			} else if ( (tmp_p[0] == 'd') && (tmp_p[1] >= '1') && (tmp_p[1] <= '2') ){	// Enable deduplication
				if ( (command_operation != 'c') && (command_operation != 't') ){
					printf("Cannot specify deduplication unless creating.\n");
				} else if (par3_ctx->deduplication != 0){
					printf("Cannot specify deduplication twice.\n");
				} else {
					par3_ctx->deduplication = tmp_p[1];
					if (add_creator_text(par3_ctx, tmp_p - 1) != 0){
						ret = RET_MEMORY_ERROR;
						goto prepare_return;
					}
				}

			} else if ( (tmp_p[0] == 'C') && (tmp_p[1] != 0) ){	// Set comment
				if (add_comment_text(par3_ctx, tmp_p + 1) != 0){
					ret = RET_MEMORY_ERROR;
					goto prepare_return;
				}

			} else if ( (strcmp(tmp_p, "abs") == 0) || (strcmp(tmp_p, "ABS") == 0) ){	// Enable absolute path
				if (tmp_p[0] == 'A'){
					par3_ctx->absolute_path = 'A';
				} else {
					par3_ctx->absolute_path = 'a';
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

	// read PAR filename
	if (argi < argc){
		if (utf8_argv != NULL){
			tmp_p = utf8_argv[argi];
		} else {
			tmp_p = argv[argi];
		}
		argi++;

		// may add ".vol32768+32768.par3"
		if (path_copy(par3_ctx->par_filename, tmp_p, _MAX_PATH - 20) == 0){
			par3_ctx->par_filename[0] = 0;
		} else {
			// PAR filename may be a relative path from current working directory.
			if (par3_ctx->base_path[0] != 0){
				// if base-path isn't empty, relative from current working directory.
				ret = get_absolute_path(file_name, par3_ctx->par_filename, _MAX_PATH - 8);
				if (ret != 0){
					printf("Failed to convert PAR filename to absolute path\n");
					ret = RET_FILE_IO_ERROR;
					goto prepare_return;
				}
				strcpy(par3_ctx->par_filename, file_name);
			}
		}
	}
	if (par3_ctx->par_filename[0] == 0){
		printf("PAR filename is not specified\n");
		ret = RET_INVALID_COMMAND;
		goto prepare_return;
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
	} else if ( ((command_operation == 'c') || (command_operation == 't')) && (par3_ctx->absolute_path != 0) ){
		// If base-path is empty at creation, current working directory becomes the absolute path.
		if (_getcwd(par3_ctx->base_path, _MAX_PATH - 4) == NULL){
			perror("Failed to get current working directory\n");
			ret = RET_FILE_IO_ERROR;
			goto prepare_return;
		}
	}

	if (par3_ctx->noise_level >= 1){
		if (par3_ctx->memory_limit != 0)
			printf("memory_limit = %I64u MB\n", par3_ctx->memory_limit >> 20);
		if (par3_ctx->search_limit != 0)
			printf("search_limit = %d ms\n", par3_ctx->search_limit);
		if (par3_ctx->block_size != 0)
			printf("Specified block size = %I64u\n", par3_ctx->block_size);
		if (par3_ctx->redundancy_size != 0)
			printf("redundancy_size = %u\n", par3_ctx->redundancy_size);
		if (par3_ctx->recovery_block_count != 0)
			printf("recovery_block_count = %I64u\n", par3_ctx->recovery_block_count);
		if (par3_ctx->first_recovery_block != 0)
			printf("first_recovery_block = %I64u\n", par3_ctx->first_recovery_block);
		if (par3_ctx->recovery_file_count != 0)
			printf("recovery_file_count = %u\n", par3_ctx->recovery_file_count);
		if (par3_ctx->recovery_file_scheme != 0)
			printf("par3_ctx->recovery_file_scheme = %c\n", par3_ctx->recovery_file_scheme);
		if (par3_ctx->deduplication != 0)
			printf("deduplication = level %c\n", par3_ctx->deduplication);
		if (command_recursive != 0)
			printf("recursive search = enable\n");
		if (par3_ctx->absolute_path != 0)
			printf("Absolute path = enable\n");
		if (par3_ctx->data_packet != 0)
			printf("Data packet = store\n");
		if (par3_ctx->base_path[0] != 0)
			printf("Base path = \"%s\"\n", par3_ctx->base_path);
		printf("PAR3 file = \"%s\"\n", par3_ctx->par_filename);
		printf("\n");
	}

	if ( (command_operation == 'c') || (command_operation == 't') ){	// Create or Trial

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

			// read relative path of an input file
			path_copy(file_name, tmp_p, _MAX_FNAME - 32);
			if (file_name[0] == 0)
				continue;
			//if (par3_ctx->noise_level >= 2){
			//	printf("argv[%d] = \"%s\"\n", argi, file_name);
			//}

			// search files by wild card matching
			ret = path_search(par3_ctx, file_name, command_recursive);
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
		if (par3_ctx->block_size == 0){
			par3_ctx->block_size = suggest_block_size(par3_ctx);
			if (par3_ctx->noise_level >= 0){
				printf("Suggested block size = %I64u\n", par3_ctx->block_size);
			}
		} else if (par3_ctx->block_size & 1){
			if (calculate_block_count(par3_ctx, par3_ctx->block_size) > 128){
				// Block size must be multiple of 2 for 16-bit Reed-Solomon Codes.
				par3_ctx->block_size += 1;
				printf("Suggested block size = %I64u\n", par3_ctx->block_size);
			}
		}
		par3_ctx->block_count = calculate_block_count(par3_ctx, par3_ctx->block_size);
		if (par3_ctx->noise_level >= 0){
			printf("Possible block count = %I64u\n", par3_ctx->block_count);
			printf("\n");
		}

		// sort input files for efficient tail packing.
		ret = sort_input_set(par3_ctx);
		if (ret != 0){
			printf("Failed to sort input sets\n");
			goto prepare_return;
		}

		if (command_operation == 'c'){
			// create recovery files
			ret = par3_create(par3_ctx);
		} else {
			// try to create recovery files
			ret = par3_trial(par3_ctx);
		}
		if (ret != 0){
			printf("Failed to create PAR3 file\n");
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
		if (command_operation != 'l'){	// Verify or Repair
			ret = par_search(par3_ctx, 1);	// Check other PAR3 files, too.
		} else {	// List
			ret = par_search(par3_ctx, 0);	// Check the specified PAR3 file only.
		}
		if (ret != 0){
			printf("Failed to search PAR3 files\n");
			goto prepare_return;
		}

		if (command_operation == 'l'){
			ret = par3_list(par3_ctx);
			if (ret != 0){
				printf("Failed to list files in PAR3 file\n");
				goto prepare_return;
			}
			if (par3_ctx->noise_level >= -1)
				printf("Listed\n");

		} else if (command_operation == 'v'){
			ret = par3_verify(par3_ctx);
			if ( (ret != 0) && (ret != RET_REPAIR_POSSIBLE) && (ret != RET_REPAIR_NOT_POSSIBLE) ){
				printf("Failed to verify with PAR3 file\n");
				goto prepare_return;
			}

		} else {
			ret = par3_repair(par3_ctx, file_name);
			if ( (ret != 0) && (ret != RET_REPAIR_FAILED) && (ret != RET_REPAIR_NOT_POSSIBLE) ){
				printf("Failed to repair with PAR3 file\n");
				goto prepare_return;
			}
		}
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
