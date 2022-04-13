
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake3/blake3.h"
#include "libpar3.h"
#include "common.h"
#include "hash.h"


// offset_next = File data is complete until here.
// find_slice = number of found slices in the file
// return 0 = complete, -1 = not enough data, -2 = too many data
// -3 = CRC of the first 16 KB is different, -4 = block data is different
// -5 = chunk tail is different, -6 = tiny chunk tail is different
// -7 = file hash is different
int check_complete_file(PAR3_CTX *par3_ctx, uint32_t file_id,
	uint64_t current_size, uint64_t *offset_next, uint64_t *find_slice)
{
	uint8_t *work_buf, buf_tail[40], buf_hash[16];
	uint32_t chunk_index, chunk_num, flag_unknown;
	int64_t block_index;
	uint64_t block_size, map_index;
	uint64_t chunk_size, tail_size;
	uint64_t file_size, file_offset;
	uint64_t size16k, crc16k, crc;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_list;
	PAR3_BLOCK_CTX *block_list;
	PAR3_MAP_CTX *map_list;
	FILE *fp;
	blake3_hasher hasher;

	if (file_id >= par3_ctx->input_file_count){
		printf("File ID is bad. %u\n", file_id);
		return RET_LOGIC_ERROR;
	}

	file_p = par3_ctx->input_file_list + file_id;
	file_size = file_p->size;
	chunk_num = file_p->chunk_num;
	if (par3_ctx->noise_level >= 1){
		printf("chunk count = %u, current file size = %I64u, original size = %I64u\n", chunk_num, current_size, file_size);
	}
	if ( (file_size == 0) && (current_size > 0) ){
		// If original file size was 0, no need to check file data.
		return -2;
	}

	// Copy variables from context to local.
	block_size = par3_ctx->block_size;
	work_buf = par3_ctx->work_buf;
	chunk_list = par3_ctx->chunk_list;
	block_list = par3_ctx->block_list;
	map_list = par3_ctx->map_list;

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

	chunk_index = file_p->chunk;	// First chunk in this file
	map_index = file_p->map;
	chunk_size = chunk_list[chunk_index].size;
	block_index = chunk_list[chunk_index].block;
	if (par3_ctx->noise_level >= 2){
		printf("first chunk = %u, size = %I64u, block index = %I64d\n", chunk_index, chunk_size, block_index);
	}
	blake3_hasher_init(&hasher);
	flag_unknown = 0;

	file_offset = 0;
	while ( (file_offset < current_size) && (file_offset < file_size) ){
		if (chunk_size > 0){	// read chunk data
			//printf("chunk_size = %I64u\n", chunk_size);
			if (chunk_size >= block_size){
				if (file_offset + block_size > current_size){	// Not enough data
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
				if (block_list[block_index].state & 64){

					// Check CRC-64 at first
					crc = crc64(work_buf, (size_t)block_size, 0);
					//printf("crc = 0x%016I64x, 0x%016I64x\n", crc, block_list[block_index].crc);
					if (crc == block_list[block_index].crc){
						blake3(work_buf, (size_t)block_size, buf_hash);
						if (memcmp(buf_hash, block_list[block_index].hash, 16) == 0){
							if (par3_ctx->noise_level >= 2){
								printf("full block[%2I64d] : map[%2I64u] chunk[%2u] file %d, offset = %I64u\n",
										block_index, map_index, chunk_index, file_id, file_offset);
							}
							map_list[map_index].find_name = file_p->name;
							map_list[map_index].find_offset = file_offset;
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
					// When current file size is smaller than original size, it's impossible to check file's hash value.
					if (current_size < file_size){
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
				if (file_offset + tail_size > current_size){	// Not enough data
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
							printf("tail block[%2I64d] : map[%2I64u] chunk[%2u] file %d, offset = %I64u, size = %I64u\n",
									block_index, map_index, chunk_index, file_id, file_offset, tail_size);
						}
						map_list[map_index].find_name = file_p->name;
						map_list[map_index].find_offset = file_offset;
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
				if (file_offset + tail_size > current_size){	// Not enough data
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
					// Tiny chunk tail isn't counted as searching slice.
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
				printf("next chunk = %u, size = %I64u, block index = %I64d\n", chunk_index, chunk_size, block_index);
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
		file_offset = 0;

		// Set block info
		chunk_index = file_p->chunk;
		chunk_num = file_p->chunk_num;
		map_index = file_p->map;
		while (chunk_num > 0){
			chunk_size = chunk_list[chunk_index].size;
			block_index = chunk_list[chunk_index].block;

			// Check all blocks in the chunk
			while (chunk_size >= block_size){
				if (map_list[map_index].find_name == NULL){	// This map was not found.
					if (par3_ctx->noise_level >= 2){
						printf("full block[%2I64d] : map[%2I64u] chunk[%2u] file %d, offset = %I64u, no checksum\n",
								block_index, map_index, chunk_index, file_id, file_offset);
					}
					map_list[map_index].find_name = file_p->name;
					map_list[map_index].find_offset = file_offset;	// Set map at ordinary position.
					*find_slice += 1;

					if ((block_list[block_index].state & 64) == 0){	// There was no checksum for this block.
						block_list[block_index].state |= (4 | 64);	// Found block and calculated its checksum.

						// It's possible to use this checksum for later search.
						crc_list_replace(par3_ctx, block_list[block_index].crc, block_index);
					}
				}

				map_index++;
				block_index++;
				file_offset += block_size;
				chunk_size -= block_size;
			}
			if (chunk_size >= 40)
				map_index++;
			file_offset += chunk_size;

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

// This checks mapping of blocks in the file.
// This uses pointer of filename, instead of file ID.
int check_damaged_file(PAR3_CTX *par3_ctx, uint8_t *filename,
	uint64_t file_size, uint64_t file_offset, uint64_t *find_slice, uint8_t *file_hash)
{
	uint8_t *work_buf, buf_hash[16];
	int64_t find_index, index;
	uint64_t block_size, read_size, slide_offset;
	uint64_t crc, crc40, crc_count, tail_count;
	uint64_t window_mask, *window_table, window_mask40, *window_table40;
	PAR3_BLOCK_CTX *block_list;
	PAR3_MAP_CTX *map_list;
	FILE *fp;
	blake3_hasher hasher;

	if (filename == NULL){
		printf("Filename is bad.\n");
		return RET_LOGIC_ERROR;
	}
	if (par3_ctx->noise_level >= 1){
		printf("current file size = %I64u, start = %I64u, \"%s\"\n", file_size, file_offset, filename);
	}
	if (file_offset >= file_size){
		return 0;
	}

	// Copy variables from context to local.
	block_size = par3_ctx->block_size;
	work_buf = par3_ctx->work_buf;
	block_list = par3_ctx->block_list;
	map_list = par3_ctx->map_list;

	// Prepare to search blocks.
	window_mask = par3_ctx->window_mask;
	window_table = par3_ctx->window_table;
	crc_count = par3_ctx->crc_count;
	window_mask40 = par3_ctx->window_mask40;
	window_table40 = par3_ctx->window_table40;
	tail_count = par3_ctx->tail_count;

	fp = fopen(filename, "rb");
	if (fp == NULL){
		perror("Failed to open input file");
		return RET_FILE_IO_ERROR;
	}

	// Move file pinter
	if (file_offset > 0){
		if (_fseeki64(fp, file_offset, SEEK_SET) != 0){
			perror("Failed to seek input file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// Read two blocks at first.
	read_size = block_size * 2;
	if (read_size > file_size - file_offset)
		read_size = file_size - file_offset;
	if (fread(work_buf, 1, (size_t)read_size, fp) != read_size){
		perror("Failed to read first blocks on input file");
		fclose(fp);
		return RET_FILE_IO_ERROR;
	}
	//printf("file_offset = %I64u, read_size = %I64u\n", file_offset, read_size);
	if (file_hash != NULL)
		blake3_hasher_update(&hasher, work_buf, (size_t)read_size);

	// Calculate CRC-64 of the first block.
	if (read_size >= block_size)
		crc = crc64(work_buf, block_size, 0);
	if (read_size >= 40)
		crc40 = crc64(work_buf, 40, 0);
	//printf("block crc = 0x%016I64x, tail crc = 0x%016I64x\n", crc, crc40);

	while (file_offset < file_size){
		// Compare current CRC-64 with full size blocks.
		if ( (file_offset + block_size <= file_size) && (crc_count > 0) ){
			//printf("file_offset = %I64u, block crc = 0x%016I64x\n", file_offset, crc);
			slide_offset = 0;
			while ( (slide_offset < block_size) && (file_offset + slide_offset + block_size <= file_size) ){
				// find_index is a index of block for the found block.
				find_index = crc_list_compare(par3_ctx, crc, work_buf + slide_offset, buf_hash);
				if (find_index >= 0){	// When a block was found while slide search.
					if (par3_ctx->noise_level >= 2){
						printf("full block[%2I64d] : offset = %I64u + %I64u\n",
								find_index, file_offset, slide_offset);
					}
					if ((block_list[find_index].state & 4) == 0){	// Only when this block was not found yet.
						// Store filename & position of this map for later reading.
						index = block_list[find_index].map;
						map_list[index].find_name = filename;
						map_list[index].find_offset = file_offset + slide_offset;
						block_list[find_index].state |= 4;
					}
					*find_slice += 1;
				}

				crc = window_mask ^ crc_slide_byte(window_mask ^ crc,
						work_buf[slide_offset + block_size], work_buf[slide_offset], window_table);
				slide_offset++;
			}
		}

		// Compare current CRC-64 with chunk tails.
		if ( (file_offset + 40 <= file_size) && (tail_count > 0) ){
			//printf("file_offset = %I64u, tail crc = 0x%016I64x\n", file_offset, crc40);
			slide_offset = 0;
			while ( (slide_offset < block_size) && (file_offset + slide_offset + 40 <= file_size) ){
				// find_index is a index of map for the found chunk tail.
				find_index = tail_list_compare(par3_ctx, crc40, work_buf + slide_offset, buf_hash);
				if (find_index >= 0){	// When a chunk tail was found while slide search.
					index = map_list[find_index].block;
					if (par3_ctx->noise_level >= 2){
						printf("tail block[%2I64u] : map[%2I64d] offset = %I64u + %I64u, tail size = %I64u, offset = %I64u\n",
								index, find_index, file_offset, slide_offset, map_list[find_index].size, map_list[find_index].tail_offset);
					}
					if (map_list[find_index].find_name == NULL){	// Only when this map was not found yet.
						// Store filename & position of this map later reading.
						map_list[find_index].find_name = filename;
						map_list[find_index].find_offset = file_offset + slide_offset;
						block_list[index].state |= 8;
					}
					*find_slice += 1;
				}

				crc40 = window_mask40 ^ crc_slide_byte(window_mask40 ^ crc40,
						work_buf[slide_offset + 40], work_buf[slide_offset], window_table40);
				slide_offset++;
			}
		}
		//printf("block crc = 0x%016I64x, tail crc = 0x%016I64x\n", crc, crc40);

		// Read next block on second position.
		file_offset += block_size;
		if (file_offset >= file_size){
			//printf("file_offset = %I64u, file_size = %I64u, EOF\n", file_offset, file_size);
			break;
		}
		read_size = block_size;
		if (file_offset + block_size >= file_size){
			// Slide block of second position to former position.
			memcpy(work_buf, work_buf + block_size, (size_t)(file_size - file_offset));
			read_size = 0;
		} else if (file_offset + block_size * 2 > file_size){
			read_size = file_size - file_offset - block_size;
		}
		//printf("file_offset = %I64u, read_size = %I64u\n", file_offset, read_size);
		if (read_size > 0){
			// Slide block of second position to former position.
			memcpy(work_buf, work_buf + block_size, (size_t)block_size);

			if (fread(work_buf + block_size, 1, (size_t)read_size, fp) != read_size){
				perror("Failed to read next block on input file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			if (file_hash != NULL)
				blake3_hasher_update(&hasher, work_buf + block_size, (size_t)read_size);
		}

/*
only when skipping slide ?

		// Calculate CRC-64 of next block.
		if (file_offset + block_size <= file_size)
			crc = crc64(work_buf, block_size, 0);
		if (file_offset + 40 <= file_size)
			crc40 = crc64(work_buf, 40, 0);
*/
	}

	if (fclose(fp) != 0){
		perror("Failed to close input file");
		return RET_FILE_IO_ERROR;
	}

	// Calculate file hash to compare with misnamed files.
	if (file_hash != NULL)
		blake3_hasher_finalize(&hasher, file_hash, 16);

	return 0;
}

