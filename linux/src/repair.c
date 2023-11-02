
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

/* Redefinition of _FILE_OFFSET_BITS must happen BEFORE including stdio.h */
#ifdef __linux__
#define _FILE_OFFSET_BITS 64
#define _fseeki64 fseeko
#elif _WIN32
#endif

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__

#elif _WIN32

// MSVC headers
#include <direct.h>
#include <sys/stat.h>

#endif

#include "libpar3.h"
#include "common.h"
#include "file.h"
#include "inside.h"
#include "verify.h"

#ifdef __linux__
static int restore_directory(char *path);

#elif _WIN32
// It will restore permissions or attributes after files are repaired.
// return 0 = no need repair, 1 = restored successfully, 2 = failed
// 0x8000 = not directory
static int restore_directory(char *path)
{
	struct _stat64 stat_buf;

	if (_stat64(path, &stat_buf) != 0){	// Missing directory
		// Create the directory
		if (_mkdir(path) == 0){
			return 1;	// Made directory
		} else {
			return 2;	// Failed
		}

	} else {
		if ((stat_buf.st_mode & _S_IFDIR) == 0)
			return 0x8000;
	}

	return 0;
}
#endif

// Reconstruct directory tree of input set
uint32_t reconstruct_directory_tree(PAR3_CTX *par3_ctx)
{
	int ret, flag_show = 0;
	uint32_t num, failed_dir_count;
	PAR3_DIR_CTX *dir_p;

	if (par3_ctx->input_dir_count == 0)
		return 0;

	failed_dir_count = 0;
	num = par3_ctx->input_dir_count;
	dir_p = par3_ctx->input_dir_list;
	while (num > 0){
		ret = restore_directory(dir_p->name);
		if (ret != 0){
			if (par3_ctx->noise_level >= 1){
				if (flag_show == 0){
					flag_show++;
					printf("\nReconstructing input directories:\n\n");
				}
			}
			if (ret == 1){
				if (par3_ctx->noise_level >= 1){
					printf("Target: \"%s\" - made.\n", dir_p->name);
				}
			} else {
				failed_dir_count++;
				if (par3_ctx->noise_level >= 1){
					printf("Target: \"%s\" - failed.\n", dir_p->name);
				}
			}
		}

		dir_p++;
		num--;
	}

	return failed_dir_count;
}

// Create temporary files for lost input files
int create_temp_file(PAR3_CTX *par3_ctx, char *temp_path)
{
	uint32_t file_count, file_index;
	PAR3_FILE_CTX *file_list;
	FILE *fp;

	if (par3_ctx->input_file_count == 0)
		return 0;

	file_count = par3_ctx->input_file_count;
	file_list = par3_ctx->input_file_list;

	// Base name of temporary file
	sprintf(temp_path, "par3_%02X%02X%02X%02X%02X%02X%02X%02X_",
			par3_ctx->set_id[0], par3_ctx->set_id[1], par3_ctx->set_id[2], par3_ctx->set_id[3],
			par3_ctx->set_id[4], par3_ctx->set_id[5], par3_ctx->set_id[6], par3_ctx->set_id[7]);

	for (file_index = 0; file_index < file_count; file_index++){
		// The input file is missing or damaged.
		if ( ((file_list[file_index].state & 3) != 0) && ((file_list[file_index].state & 4) == 0) ){
			sprintf(temp_path + 22, "%u.tmp", file_index);
			//fp = fopen(temp_path, "wbx");	// Error at over writing temporary file
			fp = fopen(temp_path, "wb");	// There is a risk of over writing existing file of same name.
			if (fp == NULL){
				perror("Failed to create temporary file");
				return RET_FILE_IO_ERROR;
			}

			if (fclose(fp) != 0){
				perror("Failed to close temporary file");
				return RET_FILE_IO_ERROR;
			}
		}
	}

	if ( (file_count == 1) && (file_list[0].state & 0x80000000) ){	// Copy PAR3 packets in unprotected chunks
		int ret;
		sprintf(temp_path + 22, "%u.tmp", 0);
		ret = copy_inside_data(par3_ctx, temp_path);
		if (ret != 0)
			return ret;
	}

	return 0;
}

// Restore content of input files
int restore_input_file(PAR3_CTX *par3_ctx, char *temp_path)
{
	char *name_prev, *find_name;
	uint8_t *work_buf, buf_tail[40];
	uint32_t file_count, file_index;
	uint32_t chunk_index, chunk_num;
	size_t slice_size;
	int64_t slice_index, file_offset;
	uint64_t block_size, chunk_size, file_size;
	PAR3_SLICE_CTX *slice_list;
	PAR3_CHUNK_CTX *chunk_list;
	PAR3_FILE_CTX *file_list;
	FILE *fp_write, *fp_read;

	if (par3_ctx->input_file_count == 0)
		return 0;

	file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	slice_list = par3_ctx->slice_list;
	chunk_list = par3_ctx->chunk_list;
	file_list = par3_ctx->input_file_list;

	// Allocate memory to read one input block
	work_buf = malloc(block_size);
	if (work_buf == NULL){
		perror("Failed to allocate memory for input data");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->work_buf = work_buf;

	// Base name of temporary file
	sprintf(temp_path, "par3_%02X%02X%02X%02X%02X%02X%02X%02X_",
			par3_ctx->set_id[0], par3_ctx->set_id[1], par3_ctx->set_id[2], par3_ctx->set_id[3],
			par3_ctx->set_id[4], par3_ctx->set_id[5], par3_ctx->set_id[6], par3_ctx->set_id[7]);

	if (par3_ctx->noise_level >= 1){
		printf("\nRestoring input files:\n\n");
	}

	name_prev = NULL;
	fp_read = NULL;
	for (file_index = 0; file_index < file_count; file_index++){
		// The input file is missing or damaged.
		if ( ((file_list[file_index].state & 3) != 0) && ((file_list[file_index].state & 4) == 0) ){
			sprintf(temp_path + 22, "%u.tmp", file_index);
			fp_write = fopen(temp_path, "r+b");
			if (fp_write == NULL){
				perror("Failed to open temporary file");
				return RET_FILE_IO_ERROR;
			}

			file_size = 0;
			chunk_index = file_list[file_index].chunk;		// index of the first chunk
			chunk_num = file_list[file_index].chunk_num;	// number of chunk descriptions
			slice_index = file_list[file_index].slice;		// index of the first slice
			//printf("chunk = %u+%u, %s\n", chunk_index, chunk_num, file_list[file_index].name);
			while (chunk_num > 0){
				chunk_size = chunk_list[chunk_index].size;
				if (chunk_size == 0){	// Unprotected Chunk Description
					// Unprotected chunk will be filled by zeros after repair.
					file_size += chunk_list[chunk_index].block;
					if (_fseeki64(fp_write, file_size, SEEK_SET) != 0){
						perror("Failed to seek temporary file");
						fclose(fp_read);
						fclose(fp_write);
						return RET_FILE_IO_ERROR;
					}

				} else {	// Protected Chunk Description
					file_size += chunk_size;
					while ( (chunk_size >= block_size) || (chunk_size >= 40) ){	// full size slice or chunk tail slice
						slice_size = slice_list[slice_index].size;
						file_offset = slice_list[slice_index].find_offset;
						find_name = slice_list[slice_index].find_name;
						if (find_name == NULL){
							printf("Input slice[%" PRId64 "] was not found.\n", slice_index);
							if (fp_read != NULL)
								fclose(fp_read);
							fclose(fp_write);
							return RET_LOGIC_ERROR;
						}

						// Read input file slice from another file.
						if ( (fp_read == NULL) || (find_name != name_prev) ){
							if (fp_read != NULL){	// Close previous another file.
								fclose(fp_read);
								fp_read = NULL;
							}
							fp_read = fopen(find_name, "rb");
							if (fp_read == NULL){
								perror("Failed to open another file");
								fclose(fp_write);
								return RET_FILE_IO_ERROR;
							}
							name_prev = find_name;
						}
						if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
							perror("Failed to seek another file");
							fclose(fp_read);
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}
						if (fread(work_buf, 1, slice_size, fp_read) != slice_size){
							perror("Failed to read full slice on input file");
							fclose(fp_read);
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}

						// Write input file slice on temporary file.
						if (fwrite(work_buf, 1, slice_size, fp_write) != slice_size){
							perror("Failed to write slice on temporary file");
							fclose(fp_read);
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}

						slice_index++;
						chunk_size -= slice_size;
					}

					if (chunk_size > 0){	// tiny chunk tail
						slice_size = chunk_size;	// Tiny chunk tail was stored in File Packet.

						// copy 1 ~ 39 bytes
						memcpy(buf_tail, &(chunk_list[chunk_index].tail_crc), 8);
						memcpy(buf_tail + 8, chunk_list[chunk_index].tail_hash, 16);
						memcpy(buf_tail + 24, &(chunk_list[chunk_index].tail_block), 8);
						memcpy(buf_tail + 32, &(chunk_list[chunk_index].tail_offset), 8);

						// Write input file slice on temporary file.
						if (fwrite(buf_tail, 1, slice_size, fp_write) != slice_size){
							perror("Failed to write tiny slice on temporary file");
							fclose(fp_read);
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}
					}

				}

				chunk_index++;
				chunk_num--;
			}

			if (fclose(fp_write) != 0){
				perror("Failed to close temporary file");
				return RET_FILE_IO_ERROR;
			}

			if (file_size != file_list[file_index].size){
				if (par3_ctx->noise_level >= 1){
					printf("Target: \"%s\" - failed.\n", temp_path);
				}
				if (fp_read != NULL)
					fclose(fp_read);
				return RET_LOGIC_ERROR;
			} else {
				file_list[file_index].state |= 0x100;
				if (par3_ctx->noise_level >= 1){
					printf("Target: \"%s\" - restored temporary.\n", temp_path);
				}
			}
		}
	}

	if (fp_read != NULL)
		fclose(fp_read);

	free(work_buf);
	par3_ctx->work_buf = NULL;

	return 0;
}

// Try to restore content of input files
int try_restore_input_file(PAR3_CTX *par3_ctx, char *temp_path)
{
	char *name_prev, *find_name;
	uint8_t *work_buf, buf_tail[40];
	uint32_t file_count, file_index;
	uint32_t chunk_index, chunk_num;
	size_t slice_size;
	int64_t slice_index, file_offset;
	uint64_t block_size, chunk_size, file_size;
	PAR3_SLICE_CTX *slice_list;
	PAR3_CHUNK_CTX *chunk_list;
	PAR3_FILE_CTX *file_list;
	FILE *fp_write, *fp_read;

	if (par3_ctx->input_file_count == 0)
		return 0;

	file_count = par3_ctx->input_file_count;
	block_size = par3_ctx->block_size;
	slice_list = par3_ctx->slice_list;
	chunk_list = par3_ctx->chunk_list;
	file_list = par3_ctx->input_file_list;

	// Allocate memory to read one input block
	work_buf = malloc(block_size);
	if (work_buf == NULL){
		perror("Failed to allocate memory for input data");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->work_buf = work_buf;

	// Base name of temporary file
	sprintf(temp_path, "par3_%02X%02X%02X%02X%02X%02X%02X%02X_",
			par3_ctx->set_id[0], par3_ctx->set_id[1], par3_ctx->set_id[2], par3_ctx->set_id[3],
			par3_ctx->set_id[4], par3_ctx->set_id[5], par3_ctx->set_id[6], par3_ctx->set_id[7]);

	if (par3_ctx->noise_level >= 1){
		printf("\nRestoring input files:\n\n");
	}

	name_prev = NULL;
	fp_read = NULL;
	for (file_index = 0; file_index < file_count; file_index++){
		// The input file is missing or damaged.
		if ( ((file_list[file_index].state & 3) != 0) && ((file_list[file_index].state & 4) == 0)
				&& ((file_list[file_index].state & 0x200) != 0) ){	// Checked repairable already
			sprintf(temp_path + 22, "%u.tmp", file_index);
			fp_write = fopen(temp_path, "wb");	// There is a risk of over writing existing file of same name.
			if (fp_write == NULL){
				perror("Failed to open temporary file");
				return RET_FILE_IO_ERROR;
			}

			file_size = 0;
			chunk_index = file_list[file_index].chunk;		// index of the first chunk
			chunk_num = file_list[file_index].chunk_num;	// number of chunk descriptions
			slice_index = file_list[file_index].slice;		// index of the first slice
			//printf("chunk = %u+%u, %s\n", chunk_index, chunk_num, file_list[file_index].name);
			while (chunk_num > 0){
				chunk_size = chunk_list[chunk_index].size;
				if (chunk_size == 0){	// Unprotected Chunk Description
					// Unprotected chunk will be filled by zeros after repair.
					file_size += chunk_list[chunk_index].block;
					if (_fseeki64(fp_write, file_size, SEEK_SET) != 0){
						perror("Failed to seek temporary file");
						fclose(fp_read);
						fclose(fp_write);
						return RET_FILE_IO_ERROR;
					}

				} else {	// Protected Chunk Description

					file_size += chunk_size;
					while ( (chunk_size >= block_size) || (chunk_size >= 40) ){	// full size slice or chunk tail slice
						slice_size = slice_list[slice_index].size;
						file_offset = slice_list[slice_index].find_offset;
						find_name = slice_list[slice_index].find_name;
						if (find_name == NULL){
							printf("Input slice[%" PRId64 "] was not found.\n", slice_index);
							if (fp_read != NULL)
								fclose(fp_read);
							fclose(fp_write);
							return RET_LOGIC_ERROR;
						}

						// Read input file slice from another file.
						if ( (fp_read == NULL) || (find_name != name_prev) ){
							if (fp_read != NULL){	// Close previous another file.
								fclose(fp_read);
								fp_read = NULL;
							}
							fp_read = fopen(find_name, "rb");
							if (fp_read == NULL){
								perror("Failed to open another file");
								fclose(fp_write);
								return RET_FILE_IO_ERROR;
							}
							name_prev = find_name;
						}
						if (_fseeki64(fp_read, file_offset, SEEK_SET) != 0){
							perror("Failed to seek another file");
							fclose(fp_read);
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}
						if (fread(work_buf, 1, slice_size, fp_read) != slice_size){
							perror("Failed to read full slice on input file");
							fclose(fp_read);
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}

						// Write input file slice on temporary file.
						if (fwrite(work_buf, 1, slice_size, fp_write) != slice_size){
							perror("Failed to write slice on temporary file");
							fclose(fp_read);
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}

						slice_index++;
						chunk_size -= slice_size;
					}

					if (chunk_size > 0){	// tiny chunk tail
						slice_size = chunk_size;	// Tiny chunk tail was stored in File Packet.

						// copy 1 ~ 39 bytes
						memcpy(buf_tail, &(chunk_list[chunk_index].tail_crc), 8);
						memcpy(buf_tail + 8, chunk_list[chunk_index].tail_hash, 16);
						memcpy(buf_tail + 24, &(chunk_list[chunk_index].tail_block), 8);
						memcpy(buf_tail + 32, &(chunk_list[chunk_index].tail_offset), 8);

						// Write input file slice on temporary file.
						if (fwrite(buf_tail, 1, slice_size, fp_write) != slice_size){
							perror("Failed to write tiny slice on temporary file");
							fclose(fp_read);
							fclose(fp_write);
							return RET_FILE_IO_ERROR;
						}
					}
				}

				chunk_index++;
				chunk_num--;
			}

			if (fclose(fp_write) != 0){
				perror("Failed to close temporary file");
				return RET_FILE_IO_ERROR;
			}

			if (file_size != file_list[file_index].size){
				if (par3_ctx->noise_level >= 1){
					printf("Target: \"%s\" - failed.\n", temp_path);
				}
				if (fp_read != NULL)
					fclose(fp_read);
				return RET_LOGIC_ERROR;
			} else {
				file_list[file_index].state |= 0x100;
				if (par3_ctx->noise_level >= 1){
					printf("Target: \"%s\" - restored temporary.\n", temp_path);
				}
			}
		}
	}

	if (fp_read != NULL)
		fclose(fp_read);

	free(work_buf);
	par3_ctx->work_buf = NULL;

	return 0;
}

// Backup damaged file by adding number at the last
static int backup_file(char *filename)
{
	char backup_name[_MAX_PATH + 8];
	int num;
	size_t len;

	strcpy(backup_name, filename);
	len = strlen(backup_name);
	if (len + 2 >= _MAX_PATH)
		return 1;

	for (num = 1; num < 10000; num++){
		sprintf(backup_name + len, ".%d", num);
		if (strlen(backup_name) >= _MAX_PATH){
			break;	// Filename became too long by added number.
		}
		if (rename(filename, backup_name) == 0){
			return 0;	// backup OK
		}
	}

	return 2;
}

// Verify repaired file and rename to original name
int verify_repaired_file(PAR3_CTX *par3_ctx, char *temp_path,
		uint32_t *missing_file_count, uint32_t *damaged_file_count, uint32_t *misnamed_file_count, uint32_t *bad_file_count)
{
	int flag_show = 0;
	char *file_name;
	int ret;
	uint32_t file_count, file_index;
	PAR3_FILE_CTX *file_list;

	if (par3_ctx->input_file_count == 0)
		return 0;

	file_count = par3_ctx->input_file_count;
	file_list = par3_ctx->input_file_list;

	// Allocate buffer to store file data temporary.
	par3_ctx->work_buf = malloc(par3_ctx->block_size);
	if (par3_ctx->work_buf == NULL){
		perror("Failed to allocate memory for input data");
		return RET_MEMORY_ERROR;
	}

	// Base name of temporary file
	sprintf(temp_path, "par3_%02X%02X%02X%02X%02X%02X%02X%02X_",
			par3_ctx->set_id[0], par3_ctx->set_id[1], par3_ctx->set_id[2], par3_ctx->set_id[3],
			par3_ctx->set_id[4], par3_ctx->set_id[5], par3_ctx->set_id[6], par3_ctx->set_id[7]);

	*missing_file_count = 0;
	*damaged_file_count = 0;
	*misnamed_file_count = 0;
	*bad_file_count = 0;
	for (file_index = 0; file_index < file_count; file_index++){
		// This input file is misnamed.
		if (file_list[file_index].state & 4){
			if (par3_ctx->noise_level >= 0){
				if (flag_show == 0){
					flag_show++;
					printf("\nVerifying repaired files:\n\n");
				}
			}

			//printf("state = 0x%08X\n", file_list[file_index].state);
			if (file_list[file_index].state & 2){	// The original file is damaged.
				// Backup damaged file
				backup_file(file_list[file_index].name);

				// Or delete damaged file by purge option ?
				// Deleting level, such like: -p, -p1, -p2
			}

			// Get wrong filename
			ret = file_list[file_index].state >> 3;	// Index of extra file
			file_name = namez_get(par3_ctx->extra_file_name, par3_ctx->extra_file_name_len, ret);

			// Correct to original filename
			if (rename(file_name, file_list[file_index].name) != 0){
				perror("Failed to rename misnamed file");

				// No need to return backup file.
				*misnamed_file_count += 1;
				if (par3_ctx->noise_level >= 0){
					printf("Target: \"%s\" - failed.\n", file_list[file_index].name);
				}

			} else if (par3_ctx->file_system & 0x10003){	// test property
				ret = test_file_system_option(par3_ctx, 1, file_list[file_index].offset, file_list[file_index].name);
				if (ret == 0){
					if (par3_ctx->noise_level >= 0){
						printf("Target: \"%s\" - repaired.\n", file_list[file_index].name);
					}
				} else {
					*bad_file_count += 1;	// Though file data was repaired, property is different.
					if (par3_ctx->noise_level >= 0){
						printf("Target: \"%s\" - failed.\n", file_list[file_index].name);
					}
				}

			} else {
				if (par3_ctx->noise_level >= 0){
					printf("Target: \"%s\" - repaired.\n", file_list[file_index].name);
				}
			}

		// This input file is missing or damaged.
		} else if ((file_list[file_index].state & 0x104) == 0x100){	// This missing or damaged file was repaired.
			if (par3_ctx->noise_level >= 0){
				if (flag_show == 0){
					flag_show++;
					printf("\nVerifying repaired files:\n\n");
				}
			}

			sprintf(temp_path + 22, "%u.tmp", file_index);
			ret = check_complete_file(par3_ctx, temp_path, file_index, file_list[file_index].size, NULL);
			if (ret > 0)
				return ret;	// error
			if (ret == 0){
				if (file_list[file_index].state & 2){
					// Backup damaged file
					backup_file(file_list[file_index].name);

					// Or delete damaged file by purge option ?
					// Deleting level, such like: -p, -p1, -p2
				}

				// Return to original filename
				if (rename(temp_path, file_list[file_index].name) != 0){
					perror("Failed to rename temporary file");

					// Delete the temporary file
					if (remove(temp_path) != 0){
						perror("Failed to delete temporary file");
					}
					if (file_list[file_index].state & 2){
						*damaged_file_count += 1;
					} else if (file_list[file_index].state & 1){
						*missing_file_count += 1;
					}
					if (par3_ctx->noise_level >= 0){
						printf("Target: \"%s\" - failed.\n", file_list[file_index].name);
					}

				} else if (par3_ctx->file_system & 0x10003){	// test property
					ret = test_file_system_option(par3_ctx, 1, file_list[file_index].offset, file_list[file_index].name);
					if (ret == 0){
						if (par3_ctx->noise_level >= 0){
							printf("Target: \"%s\" - repaired.\n", file_list[file_index].name);
						}
					} else {
						*bad_file_count += 1;	// Though file data was repaired, property is different.
						if (par3_ctx->noise_level >= 0){
							printf("Target: \"%s\" - failed.\n", file_list[file_index].name);
						}
					}

				} else {
					if (par3_ctx->noise_level >= 0){
						if (file_list[file_index].state & 0x80000000){	// Completeness of unprotected chunks is unknown.
							printf("Target: \"%s\" - protected data was repaired.\n", file_list[file_index].name);
						} else {
							printf("Target: \"%s\" - repaired.\n", file_list[file_index].name);
						}
					}
				}

			} else {	// Repaired file is bad.
				// Delete the temporary file
				if (remove(temp_path) != 0){
					perror("Failed to delete temporary file");
				}
				if (file_list[file_index].state & 2){
					*damaged_file_count += 1;
				} else if (file_list[file_index].state & 1){
					*missing_file_count += 1;
				}
				if (par3_ctx->noise_level >= 0){
					printf("Target: \"%s\" - failed.\n", file_list[file_index].name);
				}
			}

		// Not repaired files.
		} else if (file_list[file_index].state & 4){
			*misnamed_file_count += 1;
		} else if (file_list[file_index].state & 2){
			*damaged_file_count += 1;
		} else if (file_list[file_index].state & 1){
			*missing_file_count += 1;

		// Complete, but different property
		} else if ( ((file_list[file_index].state & 0x7FFF0000) != 0) && ((par3_ctx->file_system & 0x10003) != 0) ){
			if (par3_ctx->noise_level >= 0){
				if (flag_show == 0){
					flag_show++;
					printf("\nVerifying repaired files:\n\n");
				}
			}

			ret = test_file_system_option(par3_ctx, 1, file_list[file_index].offset, file_list[file_index].name);
			if (ret == 0){
				if (par3_ctx->noise_level >= 0){
					printf("Target: \"%s\" - repaired.\n", file_list[file_index].name);
				}
			} else {
				*bad_file_count += 1;
				if (par3_ctx->noise_level >= 0){
					printf("Target: \"%s\" - failed.\n", file_list[file_index].name);
				}
			}
		}
	}

	free(par3_ctx->work_buf);
	par3_ctx->work_buf = NULL;

	return 0;
}

// Reset option of directories
uint32_t reset_directory_option(PAR3_CTX *par3_ctx)
{
	int ret, flag_show = 0;
	uint32_t num, failed_dir_count;
	PAR3_DIR_CTX *dir_p;

	if (par3_ctx->input_dir_count == 0)
		return 0;

	if ( ((par3_ctx->file_system & 4) == 0) || ((par3_ctx->file_system & 3) == 0) )
		return 0;

	failed_dir_count = 0;
	num = par3_ctx->input_dir_count;
	dir_p = par3_ctx->input_dir_list;
	while (num > 0){
		ret = check_directory(par3_ctx, dir_p->name, dir_p->offset);
		if (ret & 0xFFFF0000){
			//printf("check_directory = 0x%x\n", ret);

			if (par3_ctx->noise_level >= 0){
				if (flag_show == 0){
					flag_show++;
					printf("\nReseting input directories:\n\n");
				}
			}

			ret = test_file_system_option(par3_ctx, 2, dir_p->offset, dir_p->name);
			//printf("test_file_system_option = 0x%x\n", ret);
			if (ret == 0){
				if (par3_ctx->noise_level >= 0){
					printf("Target: \"%s\" - repaired.\n", dir_p->name);
				}
			} else {
				failed_dir_count++;
				if (par3_ctx->noise_level >= 0){
					printf("Target: \"%s\" - failed.\n", dir_p->name);
				}
			}
		}

		dir_p++;
		num--;
	}

	return failed_dir_count;
}
