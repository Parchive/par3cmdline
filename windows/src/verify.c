
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
static int check_file(char *path, uint64_t *file_size)
{
	// MSVC
	struct _finddatai64_t c_file;
	intptr_t handle;

	handle = _findfirst64(path, &c_file);
	if (handle == -1)
		return 1;
	_findclose(handle);

	// Get size of existing file.
	*file_size = c_file.size;	// This may be different from original size.

	if ((c_file.attrib & _A_SUBDIR) == 1)
		return 0x8000;

	return 0;
}

/*
distinguish ?

checking complete file (compare chunks in the file)
checking damaged file (compare all maps of other files)


*/

// offset_next = File data is complete until here.
// file_slice = how many input file slices in original file
// find_slice = number of found slices in the file
// return 0 = complete, -1 = not enough data, -2 = too many data
// -3 = CRC of the first 16 KB is different, -4 = block data is different
// -5 = chunk tail is different, -6 = tiny chunk tail is different
// -7 = file hash is different
static int check_complete_file(PAR3_CTX *par3_ctx, uint32_t file_id,
	uint64_t real_size, uint64_t *offset_next,
	uint64_t *file_slice, uint64_t *find_slice)
{
	uint8_t *work_buf, buf_tail[40], buf_hash[16];
	uint32_t chunk_index, chunk_num, flag_unknown;
	uint64_t block_size, block_index, map_index;
	uint64_t chunk_size, tail_size, slice_count;
	uint64_t file_size, file_offset;
	uint64_t size16k, crc16k, crc;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_list;
	PAR3_BLOCK_CTX *block_list;
	PAR3_MAP_CTX *map_list;
	FILE *fp;
	blake3_hasher hasher;

	file_p = par3_ctx->input_file_list + file_id;
	file_size = file_p->size;
	if (par3_ctx->noise_level >= 1){
		printf("real file size = %I64u, original file size = %I64u\n", real_size, file_size);
	}
	if ( (file_size == 0) && (real_size > 0) ){
		// If original file size was 0, no need to check file data.
		return -2;
	}

	// Copy variables from context to local.
	block_size = par3_ctx->block_size;
	work_buf = par3_ctx->work_buf;
	chunk_list = par3_ctx->chunk_list;
	block_list = par3_ctx->block_list;
	map_list = par3_ctx->map_list;

	// First chunk in this file
	chunk_index = file_p->chunk;
	chunk_num = file_p->chunk_num;

	// Calculate number of input file slices in the file.
	// Because map info doesn't include tiny chunk tail, I use input file slice here.
	slice_count = 0;
	while (chunk_num > 0){
		chunk_size = chunk_list[chunk_index].size;
		slice_count += chunk_size / block_size;
		if (chunk_size % block_size != 0)
			slice_count++;

		chunk_index++;
		chunk_num--;
	}
	*file_slice = slice_count;

	fp = fopen(file_p->name, "rb");
	if (fp == NULL){
		perror("Failed to open input file");
		return RET_FILE_IO_ERROR;
	}

	// Only when stored CRC-64 isn't zero, check the first 16 KB.
	crc16k = 0;
	if (file_p->crc == 0){
		size16k = 0;
	} else if (file_size < 16384){
		size16k = file_size;
	} else {
		size16k = 16384;
	}

	chunk_index = file_p->chunk;
	chunk_num = file_p->chunk_num;
	map_index = file_p->map;
	chunk_size = chunk_list[chunk_index].size;
	block_index = chunk_list[chunk_index].block;
	if (par3_ctx->noise_level >= 2){
		printf("first chunk = %u, size = %I64u, block index = %I64u\n", chunk_index, chunk_size, block_index);
	}
	blake3_hasher_init(&hasher);
	flag_unknown = 0;

	file_offset = 0;
	while ( (file_offset < real_size) && (file_offset < file_size) ){
		if (chunk_size > 0){	// read chunk data
			//printf("chunk_size = %I64u\n", chunk_size);
			if (chunk_size >= block_size){
				if (file_offset + block_size > real_size){	// Not enough data
					fclose(fp);
					return -1;
				}
				if ( (file_offset == 0) && (size16k > 0) && (size16k < block_size) ){
					// When block size is larger than 16 KB, check the first 16 KB at first.
					if (fread(work_buf, 1, (size_t)size16k, fp) != size16k){
						perror("Failed to read the first 16 KB of input file");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
					crc16k = crc64(work_buf, (size_t)size16k, 0);
					if (crc16k != file_p->crc){
						fclose(fp);
						return -3;
					}
					if (fread(work_buf + size16k, 1, (size_t)(block_size - size16k), fp) != block_size - size16k){
						perror("Failed to read the first block of input file");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
					size16k = 0;

				} else {
					if (fread(work_buf, 1, (size_t)block_size, fp) != block_size){
						perror("Failed to read a block on input file");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
				}

				// Check CRC-64 of the first 16 KB
				if (size16k > 0){
					if (size16k <= block_size){
						crc16k = crc64(work_buf, (size_t)size16k, crc16k);
						size16k = 0;
						if (crc16k != file_p->crc){
							fclose(fp);
							return -3;
						}
					} else {	// need more data
						crc16k = crc64(work_buf, (size_t)block_size, crc16k);
						size16k -= block_size;
					}
				}

				// Comparison is possible, only when checksum exists.
				if (block_list[block_index].state & 16){

					// Check CRC-64 at first
					crc = crc64(work_buf, (size_t)block_size, 0);
					//printf("crc = 0x%016I64x, 0x%016I64x\n", crc, block_list[block_index].crc);
					if (crc == block_list[block_index].crc){
						blake3(work_buf, (size_t)block_size, buf_hash);
						if (memcmp(buf_hash, block_list[block_index].hash, 16) == 0){
							if (par3_ctx->noise_level >= 2){
								printf("full block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset = %I64u\n",
										block_index, map_index, chunk_index, file_id, file_offset);
							}
							map_list[map_index].state |= 1;
							block_list[block_index].state |= 4;
							*find_slice += 1;
						} else {	// BLAKE3 hash is different.
							block_index = -1;
						}
					} else {	// CRC-64 is different.
						block_index = -1;
					}
					if (block_index == -1){	// Block data is different.
						fclose(fp);
						return -4;
					}

				} else {	// This block's checksum is unknown.
					// When real file size is smaller than original size, it's impossible to check file's hash value.
					if (real_size < file_size){
						fclose(fp);
						return -1;
					}

					// set this checksum temporary
					block_list[block_index].crc = crc64(work_buf, (size_t)block_size, 0);
					blake3(work_buf, (size_t)block_size, block_list[block_index].hash);

					flag_unknown = 1;	// sign of unknown checksum
				}

				blake3_hasher_update(&hasher, work_buf, (size_t)block_size);
				block_index++;
				map_index++;
				chunk_size -= block_size;
				file_offset += block_size;
				if (flag_unknown == 0)
					*offset_next = file_offset;

			} else if (chunk_size >= 40){
				tail_size = chunk_size;
				if (file_offset + tail_size > real_size){	// Not enough data
					fclose(fp);
					return -1;
				}
				if ( (file_offset == 0) && (size16k > 0) && (size16k < tail_size) ){
					// When block size is larger than 16 KB, check the first 16 KB at first.
					if (fread(work_buf, 1, (size_t)size16k, fp) != size16k){
						perror("Failed to read the first 16 KB of input file");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
					crc16k = crc64(work_buf, (size_t)size16k, 0);
					if (crc16k != file_p->crc){
						fclose(fp);
						return -3;
					}
					if (fread(work_buf + size16k, 1, (size_t)(tail_size - size16k), fp) != tail_size - size16k){
						perror("Failed to read the first tail of input file");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
					size16k = 0;

				} else {
					if (fread(work_buf, 1, (size_t)tail_size, fp) != tail_size){
						perror("Failed to read a tail on input file");
						fclose(fp);
						return RET_FILE_IO_ERROR;
					}
				}

				// Check CRC-64 of the first 16 KB
				if (size16k > 0){
					if (size16k <= tail_size){
						crc16k = crc64(work_buf, (size_t)size16k, crc16k);
						size16k = 0;
						if (crc16k != file_p->crc){
							fclose(fp);
							return -3;
						}
					} else {	// need more data
						crc16k = crc64(work_buf, (size_t)tail_size, crc16k);
						size16k -= tail_size;
					}
				}

				// Check CRC-64 at first
				block_index = chunk_list[chunk_index].tail_block;
				crc = crc64(work_buf, 40, 0);	// Check the first 40-bytes only.
				if (crc == chunk_list[chunk_index].tail_crc){
					blake3(work_buf, (size_t)tail_size, buf_hash);
					if (memcmp(buf_hash, chunk_list[chunk_index].tail_hash, 16) == 0){
						if (par3_ctx->noise_level >= 2){
							printf("tail block[%2I64u] : map[%2I64u] chunk[%2u] file %d, offset = %I64u, size = %I64u\n",
									block_index, map_index, chunk_index, file_id, file_offset, tail_size);
						}
						map_list[map_index].state |= 1;
						block_list[block_index].state |= 8;
						*find_slice += 1;
					} else {	// BLAKE3 hash is different.
						block_index = -1;
					}
				} else {	// CRC-64 is different.
					block_index = -1;
				}

				if (block_index == -1){	// Tail data is different.
					fclose(fp);
					return -5;
				}
				blake3_hasher_update(&hasher, work_buf, (size_t)tail_size);
				map_index++;
				chunk_size -= tail_size;
				file_offset += tail_size;
				if (flag_unknown == 0)
					*offset_next = file_offset;

			} else if (chunk_size > 0){	// 1 ~ 39 bytes
				tail_size = chunk_size;
				if (file_offset + tail_size > real_size){	// Not enough data
					fclose(fp);
					return -1;
				}
				if (fread(work_buf, 1, (size_t)tail_size, fp) != tail_size){
					perror("Failed to read tail data on input file");
					fclose(fp);
					return RET_FILE_IO_ERROR;
				}

				// Check CRC-64 of the first 16 KB
				if (size16k > 0){
					if (size16k <= tail_size){
						crc16k = crc64(work_buf, (size_t)size16k, crc16k);
						size16k = 0;
						if (crc16k != file_p->crc){
							fclose(fp);
							return -3;
						}
					} else {	// need more data
						crc16k = crc64(work_buf, (size_t)tail_size, crc16k);
						size16k -= tail_size;
					}
				}

				// copy tail bytes
				memcpy(buf_tail, &(chunk_list[chunk_index].tail_crc), 8);
				memcpy(buf_tail + 8, chunk_list[chunk_index].tail_hash, 16);
				memcpy(buf_tail + 24, &(chunk_list[chunk_index].tail_block), 8);
				memcpy(buf_tail + 32, &(chunk_list[chunk_index].tail_offset), 8);

				// Compare bytes directly.
				if (memcmp(work_buf, buf_tail, (size_t)tail_size) == 0){
					if (par3_ctx->noise_level >= 2){
						printf("tail block no  : map no  chunk[%2u] file %d, offset = %I64u, size = %I64u\n",
								chunk_index, file_id, file_offset, tail_size);
					}
					*find_slice += 1;
				} else {	// Tail data is different.
					fclose(fp);
					return -6;
				}

				blake3_hasher_update(&hasher, work_buf, (size_t)tail_size);
				chunk_size -= tail_size;
				file_offset += tail_size;
				if (flag_unknown == 0)
					*offset_next = file_offset;
			}

		} else {	// goto next chunk
			chunk_num--;
			if (chunk_num == 0)
				break;	// When there is no chunk description anymore, exit from loop.
			chunk_index++;

			chunk_size = chunk_list[chunk_index].size;
			block_index = chunk_list[chunk_index].block;
			if (par3_ctx->noise_level >= 2){
				printf("next chunk = %u, size = %I64u, block index = %I64u\n", chunk_index, chunk_size, block_index);
			}
		}
	}

	if (fclose(fp) != 0){
		perror("Failed to close input file");
		return RET_FILE_IO_ERROR;
	}

	if (file_offset < file_size){
		// File size is smaller than original size.
		return -1;
	}

	// Check file's hash at the last.
	blake3_hasher_finalize(&hasher, buf_hash, 16);
	if (memcmp(buf_hash, file_p->hash, 16) != 0){
		// File hash is different.
		return -7;

	} else if (flag_unknown != 0){
		// Even when checksum is unknown, file data is complete.
		*offset_next = file_size;

		// Set block info
		chunk_index = file_p->chunk;
		chunk_num = file_p->chunk_num;
		map_index = file_p->map;
		while (chunk_num > 0){
			chunk_size = chunk_list[chunk_index].size;
			block_index = chunk_list[chunk_index].block;

			// Check all blocks in the chunk
			while (chunk_size >= block_size){
				if ((map_list[map_index].state & 1) == 0){	// This map was not found.
					if (par3_ctx->noise_level >= 2){
						printf("full block[%2I64u] : map[%2I64u] chunk[%2u] file %d, no checksum\n",
								block_index, map_index, chunk_index, file_id);
					}
					map_list[map_index].state |= 1;	// Found map.
					*find_slice += 1;

					if ((block_list[block_index].state & 16) == 0){	// There was no checksum for this block.
						block_list[block_index].state |= (4 | 16);	// Found block and calculated its checksum.

						// It's possible to use this checksum for later search.
						crc_list_replace(par3_ctx, block_list[block_index].crc, block_index);
					}
				}

				map_index++;
				block_index++;
				chunk_size -= block_size;
			}
			if (chunk_size >= 40)
				map_index++;

			chunk_index++;	// goto next chunk
			chunk_num--;
		}
	}

	// At last, file data of original size is complete.
	if (file_offset > file_size){
		// But, file size is larger than original size.
		return -2;
	}

	return 0;
}

// This checks chunks in the file.
static int check_chunk_map(PAR3_CTX *par3_ctx, uint32_t file_id)
{
	uint8_t *work_buf;
	uint32_t chunk_index, chunk_num;
	uint64_t block_size;
	uint64_t chunk_size, find_index;
	uint64_t file_size, file_offset, read_size;
	uint64_t map_count, map_find;
	uint64_t crc16k, crc_count;
	uint64_t window_mask, *window_table;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_p, *chunk_list;
	PAR3_CMP_CTX *crc_list;
	FILE *fp;
	blake3_hasher hasher;

	// Copy variables from context to local.
	block_size = par3_ctx->block_size;
	work_buf = par3_ctx->work_buf;

	// Prepare to search blocks.
	window_mask = par3_ctx->window_mask;
	window_table = par3_ctx->window_table;
	crc_list = par3_ctx->crc_list;
	crc_count = par3_ctx->crc_count;

	file_p = par3_ctx->input_file_list + file_id;
	printf("file size = %I64u \"%s\"\n", file_p->size, file_p->name);
	if (file_p->size == 0)
		return 0;	// If file size is 0, no need to check file data.

	// First chunk in this file
	chunk_p = par3_ctx->chunk_list + file_p->chunk;
	printf("chunk[%2u] : size = %I64u, index = %I64u\n", file_p->chunk, chunk_p->size, chunk_p->block);
	chunk_size = chunk_p->size;
	find_index = chunk_p->block;

	// Calculate number of map in the file
	chunk_list = par3_ctx->chunk_list;
	chunk_index = file_p->chunk;
	chunk_num = file_p->chunk_num;
	map_count = 0;
	while (chunk_num > 0){
		chunk_size = chunk_list[chunk_index].size;
		map_count += chunk_size / block_size;
		if (chunk_size % block_size >= 40)
			map_count++;

		chunk_index++;
		chunk_num--;
	}
	printf("map count = %I64u\n", map_count);

	fp = fopen(file_p->name, "rb");
	if (fp == NULL){
		perror("Failed to open input file");
		return RET_FILE_IO_ERROR;
	}

	// Read two blocks at first.
	file_size = file_p->size;
	read_size = block_size * 2;
	if (read_size > file_size)
		read_size = file_size;
	if (fread(work_buf, 1, (size_t)read_size, fp) != read_size){
		perror("Failed to read first blocks on input file");
		fclose(fp);
		return RET_FILE_IO_ERROR;
	}

	// calculate CRC-64 of the first 16 KB
	if (read_size < 16384){
		crc16k = crc64(work_buf, (size_t)read_size, 0);
	} else {
		crc16k = crc64(work_buf, 16384, 0);
	}
	blake3_hasher_init(&hasher);
	blake3_hasher_update(&hasher, work_buf, (size_t)read_size);


	file_offset = 0;
	while (file_offset < file_size){
	
	
	
		file_offset += block_size;
	}

	if (fclose(fp) != 0){
		perror("Failed to close input file");
		return RET_FILE_IO_ERROR;
	}



	return 0;
}

// Check existense and content of each input file.
int verify_input_file(PAR3_CTX *par3_ctx)
{
	int ret;
	uint32_t num;
	uint64_t real_size, file_offset, file_slice, find_slice;
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

	// Allocate buffer to store file data temporary.
	par3_ctx->work_buf = malloc(par3_ctx->block_size * 2);
	if (par3_ctx->work_buf == NULL){
		perror("Failed to allocate memory for temporary file data");
		return RET_MEMORY_ERROR;
	}

	file_p = par3_ctx->input_file_list;
	for (num = 0; num < par3_ctx->input_file_count; num++){
		ret = check_file(file_p->name, &real_size);
		if ( (ret == 0) && ( (file_p->size > 0) || (real_size > 0) ) ){
			file_offset = 0;
			file_slice = find_slice = 0;

			//printf("Target: \"%s\" - exist (not verified yet).\n", file_p->name);

			printf("Opening: \"%s\"\n", file_p->name);
			//ret = check_chunk_map(par3_ctx, num);
			ret = check_complete_file(par3_ctx, num, real_size, &file_offset, &file_slice, &find_slice);
			if (ret > 0)
				return ret;	// error
			
			printf("ret = %d, size = %I64u, offset = %I64u, slice = %I64u / %I64u\n",
					ret, real_size, file_offset, find_slice, file_slice);



		} else {
			printf("Target: \"%s\"", file_p->name);
			if (ret == 0){
				printf(" - found.\n");
			} else if (ret == 1){
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

