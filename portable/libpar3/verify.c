#include "libpar3.h"

#include "common.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "file.h"
#include "verify.h"


// This will check permission and attributes in future.
// return 0 = exist, 1 = missing
// 0x8000 = not directory
// 0x****0000 = different property (timestamp, permission, or attribute)
int check_directory(PAR3_CTX *par3_ctx, char *path, int64_t offset)
{
	struct _stat64 stat_buf;

	// Check infomation, only when scuucess.
	if (_stat64(path, &stat_buf) != 0)
		return 1;

	if (!S_ISDIR(stat_buf.st_mode))
		return 0x8000;

	if ( (offset >= 0) && ((par3_ctx->file_system & 4) != 0) && ((par3_ctx->file_system & 3) != 0) ){
		//printf("offset of Directory Packet = %"PRId64"\n", offset);
		return check_file_system_option(par3_ctx, 2, offset, &stat_buf);
	}

	return 0;
}


// Check existense of each input directory.
// Return number of missing directories.
void check_input_directory(PAR3_CTX *par3_ctx, uint32_t *missing_dir_count, uint32_t *bad_dir_count)
{
	int ret;
	uint32_t num;
	PAR3_DIR_CTX *dir_p;

	if (par3_ctx->input_dir_count == 0)
		return;

	if (par3_ctx->noise_level >= -1){
		printf("\nVerifying input directories:\n\n");
	}

	num = par3_ctx->input_dir_count;
	dir_p = par3_ctx->input_dir_list;
	while (num > 0){
		if (par3_ctx->noise_level >= -1){
			printf("Target: \"%s\"", dir_p->name);
		}
		ret = check_directory(par3_ctx, dir_p->name, dir_p->offset);
		//printf("\n check_directory = 0x%x\n", ret);
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
			*missing_dir_count += 1;
			if (par3_ctx->noise_level >= -1){
				printf(" - not directory.\n");
			}
		} else if (ret & 0xFFFF0000){
			*bad_dir_count += 1;
			if (par3_ctx->noise_level >= -1){
				if ((ret & 0xFFFF0000) == 0x10000){
					printf(" - different timestamp.\n");
				} else if ((ret & 0xFFFF0000) == 0x20000){
					printf(" - different permissions.\n");
				} else {
					printf(" - different property.\n");
				}
			}
		} else {
			if (par3_ctx->noise_level >= -1){
				printf(" - unknown.\n");
			}
		}

		dir_p++;
		num--;
	}
}



// This will check permission and attributes, only when you set an option.
// return 0 = exist, 1 = missing
// 0x8000 = not file
// 0x****0000 = different property (timestamp, permission, or attribute)
static int check_file(PAR3_CTX *par3_ctx, char *path, uint64_t *current_size, int64_t offset)
{
	struct _stat64 stat_buf;

	// Check infomation, only when scuucess.
	if (_stat64(path, &stat_buf) != 0)
		return 1;

	// Get size of existing file.
	*current_size = stat_buf.st_size;	// This may be different from original size.

	if (!S_ISREG(stat_buf.st_mode))
		return 0x8000;

	if ( (offset >= 0) && (par3_ctx->file_system & 0x10003) ){
		//printf("offset of File Packet = %"PRId64"\n", offset);
		return check_file_system_option(par3_ctx, 1, offset, &stat_buf);
	}

	return 0;
}


// Check existense and content of each input file.
int verify_input_file(PAR3_CTX *par3_ctx, uint32_t *missing_file_count, uint32_t *damaged_file_count, uint32_t *bad_file_count)
{
	int ret;
	uint32_t num;
	uint64_t current_size, file_offset, file_damage;
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
		printf("Number of full size block = %"PRIu64", chunk tail = %"PRIu64"\n", par3_ctx->crc_count, par3_ctx->tail_count);
/*
		// for debug
		for (uint64_t i = 0; i < par3_ctx->crc_count; i++){
			printf("crc_list[%2"PRIu64"] = 0x%016"PRIx64" , block = %"PRIu64"\n", i, par3_ctx->crc_list[i].crc, par3_ctx->crc_list[i].index);
		}
		for (uint64_t i = 0; i < par3_ctx->tail_count; i++){
			printf("tail_list[%2"PRIu64"] = 0x%016"PRIx64" , slice = %"PRIu64"\n", i, par3_ctx->tail_list[i].crc, par3_ctx->tail_list[i].index);
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
		ret = check_file(par3_ctx, file_p->name, &current_size, file_p->offset);
		//printf("check_file = 0x%x, size = %"PRIu64"\n", ret, current_size);
		file_p->state |= ret;
		if ( ((ret & 0xFFFF) == 0) && ( (file_p->size > 0) || (current_size > 0) ) ){
			if (par3_ctx->noise_level >= 0){
				printf("Opening: \"%s\"\n", file_p->name);
			}
			file_offset = 0;
			ret = check_complete_file(par3_ctx, file_p->name, num, current_size, &file_offset);
			//printf("ret = %d, size = %"PRIu64", offset = %"PRIu64"\n", ret, current_size, file_offset);
			if (ret > 0)
				return ret;	// error
			if (ret == 0){
				if (file_p->state & 0x7FFF0000){
					*bad_file_count += 1;
					if (par3_ctx->noise_level >= -1){
						if ((file_p->state & 0x7FFF0000) == 0x10000){
							printf("Target: \"%s\" - different timestamp.\n", file_p->name);
						} else if ((file_p->state & 0x7FFF0000) == 0x20000){
							printf("Target: \"%s\" - different permissions.\n", file_p->name);
						} else {
							printf("Target: \"%s\" - different property.\n", file_p->name);
						}
					}
				} else {
					// While file data is complete, file name may be different case on Windows PC.
					// Because Windows OS is case insensitive, I ignore the case, too.
					if (par3_ctx->noise_level >= -1){
						if (file_p->state & 0x80000000){	// Completeness of unprotected chunks is unknown.
							printf("Target: \"%s\" - protected data is complete.\n", file_p->name);
						} else {
							printf("Target: \"%s\" - complete.\n", file_p->name);
						}
					}
				}
			} else {
				file_p->state |= 2;
				*damaged_file_count += 1;

				// Start slide search after the last found block position.
				ret = check_damaged_file(par3_ctx, file_p->name, current_size, file_offset, &file_damage, NULL);
				//printf("ret = %d, size = %"PRIu64", offset = %"PRIu64", damage = %"PRIu64"\n",
				//		ret, current_size, file_offset, file_damage);
				if (ret != 0)
					return ret;
				if (par3_ctx->noise_level >= -1){
					printf("Target: \"%s\" - damaged. %"PRIu64" of %"PRIu64" bytes available.\n",
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
				*missing_file_count += 1;
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

// Check extra files and misnamed files.
int verify_extra_file(PAR3_CTX *par3_ctx, uint32_t *missing_file_count, uint32_t *damaged_file_count, uint32_t *misnamed_file_count)
{
	int ret, flag_show = 0;
	char *list_name;
	size_t len, off, list_len;
	uint8_t buf_hash[16], *tmp_p;
	uint32_t num, extra_id;
	uint64_t current_size, file_damage;
	PAR3_FILE_CTX *file_p;

	if (par3_ctx->extra_file_name_len == 0)
		return 0;

	extra_id = 0;
	list_name = par3_ctx->extra_file_name;
	list_len = par3_ctx->extra_file_name_len;
	off = 0;
	while (off < list_len){
		len = strlen(list_name + off);

		if (par3_ctx->noise_level >= 0){
			if (flag_show == 0){
				flag_show++;
				printf("\nScanning extra files:\n\n");
			}

			printf("Opening: \"%s\"\n", list_name + off);
		}

		// Get file size
		ret = check_file(par3_ctx, list_name + off, &current_size, -1);
		if ((ret & 0xFFFF) != 0){
			if (par3_ctx->noise_level >= -1){
				printf("Target: \"%s\" - unknown.\n", list_name + off);
			}
			extra_id++;
			off += len + 1;	// goto next filename
			break;
		}

		// Check possibility of misnamed file
		tmp_p = NULL;
		file_p = par3_ctx->input_file_list;
		num = par3_ctx->input_file_count;
		while (num > 0){
			// No need to compare to compelete input files.
			if (file_p->state & (1 | 2)){	// missing or damaged
				if (file_p->size == current_size){
					//printf("Calculate file hash to check misnamed file later.\n");
					tmp_p = buf_hash;
					break;
				}
			}

			file_p++;
			num--;
		}

		// Calculate file hash to find misnamed file later.
		ret = check_damaged_file(par3_ctx, list_name + off, current_size, 0, &file_damage, tmp_p);
		//printf("ret = %d, size = %"PRIu64", damage = %"PRIu64"\n", ret, current_size, file_damage);
		if (ret != 0)
			return ret;

		if (tmp_p != NULL){	// Check misnamed file here
/*
// for debug
printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	buf_hash[0], buf_hash[1], buf_hash[2], buf_hash[3],
	buf_hash[4], buf_hash[5], buf_hash[6], buf_hash[7],
	buf_hash[8], buf_hash[9], buf_hash[10], buf_hash[11],
	buf_hash[12], buf_hash[13], buf_hash[14], buf_hash[15]);
*/

			// Compare size and hash to find misnamed file.
			file_p = par3_ctx->input_file_list;
			num = par3_ctx->input_file_count;
			while (num > 0){
				// No need to compare to compelete input files.
				if (file_p->state & (1 | 2)){	// missing or damaged
					if (file_p->size == current_size){
						if (memcmp(file_p->hash, buf_hash, 16) == 0){
							*misnamed_file_count += 1;
							if (file_p->state & 1){	// When this was missing file.
								*missing_file_count -= 1;
							} else if (file_p->state & 2){	// When this was damaged file.
								*damaged_file_count -= 1;
							}
							file_p->state |= (extra_id << 3) | 4;

							//printf("Extra file[%u] is misnamed file of \"%s\".\n", extra_id, file_p->name);
							ret = 4;
							break;
						}
					}
				}

				file_p++;
				num--;
			}
		}

		if (par3_ctx->noise_level >= -1){
			if (ret & 4){
				printf("Target: \"%s\" - is a match for \"%s\".\n", list_name + off, file_p->name);
			} else {
				printf("Target: \"%s\" - %"PRIu64" of %"PRIu64" bytes available.\n",
						list_name + off, current_size - file_damage, current_size);
			}
		}

		extra_id++;
		off += len + 1;	// goto next filename
	}

	return 0;
}

