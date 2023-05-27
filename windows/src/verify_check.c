
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// MSVC headers
#include <io.h>

#include "blake3/blake3.h"
#include "libpar3.h"
#include "common.h"
#include "hash.h"


/*
offset_next = File data is complete until here.
When checking after repair, offset_next should be NULL.

return 0 = complete, -1 = not enough data, -2 = too many data
 -3 = CRC of the first 16 KB is different, -4 = block data is different
 -5 = chunk tail is different, -6 = tiny chunk tail is different
 -7 = file hash is different
*/
int check_complete_file(PAR3_CTX *par3_ctx, char *filename, uint32_t file_id,
	uint64_t current_size, uint64_t *offset_next)
{
	uint8_t *work_buf, buf_tail[40], buf_hash[16];
	uint32_t chunk_index, chunk_num, flag_unknown;
	int64_t block_index;
	uint64_t block_size, slice_index;
	uint64_t chunk_size, tail_size;
	uint64_t file_size, file_offset;
	uint64_t size16k, crc16k, crc;
	PAR3_FILE_CTX *file_p;
	PAR3_CHUNK_CTX *chunk_list;
	PAR3_BLOCK_CTX *block_list;
	PAR3_SLICE_CTX *slice_list;
	FILE *fp;
	blake3_hasher hasher;

	if (filename == NULL){
		printf("File name is bad.\n");
		return RET_LOGIC_ERROR;
	}
	if (file_id >= par3_ctx->input_file_count){
		printf("File ID is bad. %u\n", file_id);
		return RET_LOGIC_ERROR;
	}

	file_p = par3_ctx->input_file_list + file_id;
	file_size = file_p->size;
	chunk_num = file_p->chunk_num;
	if (offset_next != NULL){	// Don't show this after repair.
		if (par3_ctx->noise_level >= 1){
			printf("chunk count = %u, current file size = %I64u, original size = %I64u\n", chunk_num, current_size, file_size);
		}
		if ( (file_p->state & 0x80000000) && (par3_ctx->noise_level >= 2) ){
			chunk_list = par3_ctx->chunk_list;
			block_index = 0;
			chunk_index = file_p->chunk;
			while (chunk_num > 0){
				if (chunk_list[chunk_index].size == 0)
					block_index++;
				chunk_index++;
				chunk_num--;
			}
			printf("Number of unprotected chunk = %I64d\n", block_index);
			chunk_num = file_p->chunk_num;
		}
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
	slice_list = par3_ctx->slice_list;

	fp = fopen(filename, "rb");
	if (fp == NULL){
		perror("Failed to open input file");
		return RET_FILE_IO_ERROR;
	}

	if (offset_next == NULL){	// Check file size after repair
		int file_no = _fileno(fp);
		if (file_no >= 0){
			current_size = _filelengthi64(file_no);
			//printf("file_size = %I64u, current_size = %I64u\n", file_size, current_size);
			if (current_size < file_size){
				fclose(fp);
				return -1;
			} else if (current_size > file_size){
				fclose(fp);
				return -2;
			}
		}
	}

	// Only when stored CRC-64 is valid, check the first 16 KB.
	crc16k = 0;
	if (file_p->state & 0x80000000){	// There is Unprotected Chunk Description. Such like "PAR inside".
		size16k = 0;
	} else if (file_size < 16384){
		size16k = file_size;
	} else {
		size16k = 16384;
	}

	chunk_index = file_p->chunk;	// First chunk in this file
	slice_index = file_p->slice;
	chunk_size = chunk_list[chunk_index].size;
	block_index = chunk_list[chunk_index].block;
	if (par3_ctx->noise_level >= 3){
		printf("first chunk = %u, size = %I64u, block index = %I64d\n", chunk_index, chunk_size, block_index);
	}
	blake3_hasher_init(&hasher);
	flag_unknown = 0;

	file_offset = 0;
	while (chunk_size == 0){	// zeros if not protected
		// Seek to end of unprotected chunk
		if (_fseeki64(fp, block_index, SEEK_CUR) != 0){
			perror("Failed to seek Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
		file_offset += block_index;
		chunk_num--;
		if (chunk_num > 0){
			chunk_index++;
			chunk_size = chunk_list[chunk_index].size;
			block_index = chunk_list[chunk_index].block;
			if (par3_ctx->noise_level >= 3){
				printf("next chunk = %u, size = %I64u, block index = %I64d\n", chunk_index, chunk_size, block_index);
			}
		}
	}
	while ( (file_offset < current_size) && (file_offset < file_size) ){
		if (chunk_size > 0){	// read chunk data
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
							if (par3_ctx->noise_level >= 3){
								printf("full block[%2I64d] : slice[%2I64u] chunk[%2u] file %d, offset = %I64u\n",
										block_index, slice_index, chunk_index, file_id, file_offset);
							}
							slice_list[slice_index].find_name = file_p->name;
							slice_list[slice_index].find_offset = file_offset;
							block_list[block_index].state |= 4;
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
				slice_index++;
				chunk_size -= block_size;
				file_offset += block_size;
				if ( (flag_unknown == 0) && (offset_next != NULL) )
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
						if (par3_ctx->noise_level >= 3){
							printf("tail block[%2I64d] : slice[%2I64u] chunk[%2u] file %d, offset = %I64u, size = %I64u\n",
									block_index, slice_index, chunk_index, file_id, file_offset, tail_size);
						}
						slice_list[slice_index].find_name = file_p->name;
						slice_list[slice_index].find_offset = file_offset;
						block_list[block_index].state |= 8;
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
				slice_index++;
				chunk_size -= tail_size;
				file_offset += tail_size;
				if ( (flag_unknown == 0) && (offset_next != NULL) )
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
					if (par3_ctx->noise_level >= 3){
						printf("tail block no  : slice no  chunk[%2u] file %d, offset = %I64u, size = %I64u\n",
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
				if ( (flag_unknown == 0) && (offset_next != NULL) )
					*offset_next = file_offset;
			}

		} else {	// goto next chunk
			chunk_num--;
			if (chunk_num == 0)
				break;	// When there is no chunk description anymore, exit from loop.
			chunk_index++;

			chunk_size = chunk_list[chunk_index].size;
			block_index = chunk_list[chunk_index].block;
			if (par3_ctx->noise_level >= 3){
				printf("next chunk = %u, size = %I64u, block index = %I64d\n", chunk_index, chunk_size, block_index);
			}
			if (chunk_size == 0){	// zeros if not protected
				// Seek to end of unprotected chunk
				if (_fseeki64(fp, block_index, SEEK_CUR) != 0){
					perror("Failed to seek Outside file");
					fclose(fp);
					return RET_FILE_IO_ERROR;
				}
				file_offset += block_index;
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
		if (mem_or16(file_p->hash) != 0){	// Ignore case of zero bytes, as it was not calculated.
			// File hash is different.
			return -7;
		}

	} else if (flag_unknown != 0){
		// Even when checksum is unknown, file data is complete.
		if (offset_next != NULL)
			*offset_next = file_size;
		file_offset = 0;

		// Set block info
		chunk_index = file_p->chunk;
		chunk_num = file_p->chunk_num;
		slice_index = file_p->slice;
		while (chunk_num > 0){
			chunk_size = chunk_list[chunk_index].size;
			block_index = chunk_list[chunk_index].block;

			if (chunk_size == 0){	// Unprotected Chunk Description
				file_offset += block_index;

			} else {	// Protected Chunk Description
				// Check all blocks in the chunk
				while (chunk_size >= block_size){
					if (slice_list[slice_index].find_name == NULL){	// When this slice was not found.
						if (par3_ctx->noise_level >= 3){
							printf("full block[%2I64d] : slice[%2I64u] chunk[%2u] file %d, offset = %I64u, no checksum\n",
									block_index, slice_index, chunk_index, file_id, file_offset);
						}
						slice_list[slice_index].find_name = file_p->name;
						slice_list[slice_index].find_offset = file_offset;	// Set slice at ordinary position.

						if ((block_list[block_index].state & 64) == 0){	// There was no checksum for this block.
							block_list[block_index].state |= (4 | 64);	// Found block and calculated its checksum.

							// It's possible to use this checksum for later search.
							crc_list_replace(par3_ctx, block_list[block_index].crc, block_index);
						}
					}

					slice_index++;
					block_index++;
					file_offset += block_size;
					chunk_size -= block_size;
				}
				if (chunk_size >= 40)
					slice_index++;
				file_offset += chunk_size;
			}

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

#define CHECK_SLIDE_INTERVAL 8
#define CHECK_SLIDE_RANGE 10

// This checks available slices in the file.
// This uses pointer of filename, instead of file ID.
int check_damaged_file(PAR3_CTX *par3_ctx, char *filename,
	uint64_t file_size, uint64_t file_offset, uint64_t *file_damage, uint8_t *file_hash)
{
	uint8_t *work_buf, buf_hash[16], buf_hash2[16];
	int flag_slide, hash_counter;
	int64_t find_index, block_index, slice_index;
	int64_t crc_count, tail_count;
	int64_t next_offset, next_slice, slice_count;
	uint64_t block_size, read_size, slide_offset, slide_start;
	uint64_t crc, crc40, tail_size, temp_crc;
	uint64_t uniform_start, uniform_end, hash_offset;
	uint64_t window_mask, *window_table, window_mask40, *window_table40;
	uint64_t damage_size, find_last, find_min, find_max;
	PAR3_BLOCK_CTX *block_list;
	PAR3_SLICE_CTX *slice_list;
	PAR3_CHUNK_CTX *chunk_list;
	PAR3_CMP_CTX *crc_list, *tail_list;
	FILE *fp;
	clock_t time_slide, time_limit;
	blake3_hasher hasher;

	if (filename == NULL){
		printf("File name is bad.\n");
		return RET_LOGIC_ERROR;
	}
	if (file_offset >= file_size){
		if (file_damage != NULL)
			*file_damage = 0;
		return 0;
	}
	if (par3_ctx->noise_level >= 1){
		printf("current file size = %I64u, start = %I64u, \"%s\"\n", file_size, file_offset, filename);
	}

	// File data till file_offset is available.
	damage_size = 0;
	find_last = find_max = file_offset;

	// Copy variables from context to local.
	block_size = par3_ctx->block_size;
	slice_count = par3_ctx->slice_count;
	work_buf = par3_ctx->work_buf;
	block_list = par3_ctx->block_list;
	slice_list = par3_ctx->slice_list;
	chunk_list = par3_ctx->chunk_list;

	// Set time limit for slide search
	if (par3_ctx->search_limit != 0){
		time_limit = par3_ctx->search_limit;
	} else {
		time_limit = 100;	// Time out is 100 ms by default.
	}

	// Prepare to search blocks.
	window_mask = par3_ctx->window_mask;
	window_table = par3_ctx->window_table;
	window_mask40 = par3_ctx->window_mask40;
	window_table40 = par3_ctx->window_table40;

	// Copy CRC-list for local usage.
	crc_count = par3_ctx->crc_count;
	crc_list = par3_ctx->crc_list + crc_count; // Allocated memory for CRC-list was double size.
	memcpy(crc_list, par3_ctx->crc_list, sizeof(PAR3_CMP_CTX) * crc_count);
	tail_count = par3_ctx->tail_count;
	tail_list = par3_ctx->tail_list + tail_count;
	memcpy(tail_list, par3_ctx->tail_list, sizeof(PAR3_CMP_CTX) * tail_count);
	// It's possible to remove items from the list, when a slice was found in this file.

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
	if (file_hash != NULL){
		blake3_hasher_init(&hasher);
		blake3_hasher_update(&hasher, work_buf, (size_t)read_size);
	}

	// Calculate CRC-64 of the first block.
	if ( (crc_count > 0) && (read_size >= block_size) )
		crc = crc64(work_buf, block_size, 0);
	if ( (tail_count > 0) && (read_size >= 40) )
		crc40 = crc64(work_buf, 40, 0);
	//printf("block crc = 0x%016I64x, tail crc = 0x%016I64x\n", crc, crc40);

	next_offset = -1;
	while (file_offset < file_size){
		// Prepare to check range of found slices
		find_min = file_size;

		// Prepare to check range of uniform bytes.
		uniform_start = 0xFFFFFFFFFFFFFFFF;
		uniform_end = 0;

		// Check predicted slice in orderly position at first.
		flag_slide = 0;
		slide_start = 0;
		if (next_offset >= 0){
			slide_offset = next_offset;
			slice_index = next_slice;
			next_offset = -1;	// Copied values and reset
			tail_size = slice_list[slice_index].size;
			//printf("Check at first, offset = %I64d, slice = %I64d, size = %I64u\n", slide_offset, slice_index, tail_size);
			if (tail_size == block_size){	// Full size slice
				block_index = slice_list[slice_index].block;	// index of block
				temp_crc = crc64(work_buf + slide_offset, block_size, 0);
				if (temp_crc == block_list[block_index].crc){
					blake3(work_buf + slide_offset, block_size, buf_hash);
					if (memcmp(buf_hash, block_list[block_index].hash, 16) == 0){
						if (par3_ctx->noise_level >= 3){
							printf("p fu block[%2I64d] : slice[%2I64d] offset = %I64u + %I64u\n",
									block_index, slice_index, file_offset, slide_offset);
						}
						if ((block_list[block_index].state & 4) == 0){	// When this block was not found yet.
							// Store filename & position of this slice for later reading.
							slice_list[slice_index].find_name = filename;
							slice_list[slice_index].find_offset = file_offset + slide_offset;
							block_list[block_index].state |= 4;
						}
						if (find_min > file_offset + slide_offset)
							find_min = file_offset + slide_offset;
						if (find_max < file_offset + slide_offset + block_size)
							find_max = file_offset + slide_offset + block_size;

						// When CRC and BLAKE3 match, remove this item from crc_list.
						find_index = cmp_list_search_index(par3_ctx, temp_crc, block_index, crc_list, crc_count);
						if (find_index >= 0){
							if (find_index + 1 < crc_count)
								memmove(crc_list + find_index, crc_list + find_index + 1, sizeof(PAR3_CMP_CTX) * (crc_count - find_index - 1));
							crc_count--;
							//printf("Remove item[%I64d] : block[%I64u] from crc_list. crc_count = %I64u\n", find_index, block_index, crc_count);
						}

						// When predicted slice was found, cancel slide search.
						if (slice_list[slice_index].next == -1){	// There is only one slice for the found block.
							if (slice_index + 1 < slice_count){	// There is next slice
								if (slice_list[slice_index + 1].chunk == slice_list[slice_index].chunk){	// Belong to same chunk
									next_offset = slide_offset;
									next_slice = slice_index + 1;
									flag_slide |= 7;	// Cancel slide and calculate CRC-64 after reading next block.
								}
							}
						}
					}
				}

			} else {	// Chunk tail slice
				temp_crc = crc64(work_buf + slide_offset, 40, 0);
				if (temp_crc == chunk_list[slice_list[slice_index].chunk].tail_crc){
					blake3(work_buf + slide_offset, tail_size, buf_hash);
					if (memcmp(buf_hash, chunk_list[slice_list[slice_index].chunk].tail_hash, 16) == 0){
						block_index = slice_list[slice_index].block;	// index of block
						if (par3_ctx->noise_level >= 3){
							printf("p ta block[%2I64d] : slice[%2I64d] offset = %I64u + %I64u, tail size = %I64u, offset = %I64u\n",
									block_index, slice_index, file_offset, slide_offset, tail_size, slice_list[slice_index].tail_offset);
						}
						if (slice_list[slice_index].find_name == NULL){	// When this slice was not found yet.
							// Store filename & position of this slice for later reading.
							slice_list[slice_index].find_name = filename;
							slice_list[slice_index].find_offset = file_offset + slide_offset;
							block_list[block_index].state |= 8;
						}
						if (find_min > file_offset + slide_offset)
							find_min = file_offset + slide_offset;
						if (find_max < file_offset + slide_offset + tail_size)
							find_max = file_offset + slide_offset + tail_size;

						// When CRC and BLAKE3 match, remove this item from tail_list.
						find_index = cmp_list_search_index(par3_ctx, temp_crc, slice_index, tail_list, tail_count);
						if (find_index >= 0){
							if (find_index + 1 < tail_count)
								memmove(tail_list + find_index, tail_list + find_index + 1, sizeof(PAR3_CMP_CTX) * (tail_count - find_index - 1));
							tail_count--;
							//printf("Remove item[%I64d] : block[%I64u] from tail_list. tail_count = %I64u\n", find_index, block_index, tail_count);
						}

						// Even when predicted slice was found, continue slide search.
						slide_start = slide_offset + tail_size;	// Set starting offset to the last of chunk tail.
						if (slide_start >= block_size){	// When slide will be canceled.
							flag_slide |= 7;	// Cancel slide and calculate CRC-64 after reading next block.
						} else {
							// Calculate CRC-64 to slide later.
							if ( (crc_count > 0) && (file_offset + slide_start + block_size <= file_size) ){
								//printf("Calculate CRC-64 of next block.\n");
								crc = crc64(work_buf + slide_start, block_size, 0);
							}
							if ( (tail_count > 0) && (file_offset + slide_start + 40 <= file_size) ){
								//printf("Calculate CRC-64 of next tail.\n");
								crc40 = crc64(work_buf + slide_start, 40, 0);
							}
						}
					}
				}
			}
		} else {
			next_offset = -1;
		}

		// Compare current CRC-64 with full size blocks.
		if ( ((flag_slide & 4) == 0) && (crc_count > 0) && (file_offset + slide_start + block_size <= file_size) ){
			//printf("slide: offset = %I64u + %I64u, block crc = 0x%016I64x\n", file_offset, slide_start, crc);
			hash_counter = 0;
			hash_offset = 0;
			time_slide = clock();	// Store starting time of slide search.
			slide_offset = slide_start;
			while ( (slide_offset < block_size) && (file_offset + slide_offset + block_size <= file_size) ){
				tail_size = 0;
				// find_index is the first index of the matching CRC-64. There may be multiple items.
				find_index = cmp_list_search(par3_ctx, crc, crc_list, crc_count);
				while (find_index >= 0){	// When CRC-64 is same.
					block_index = crc_list[find_index].index;	// index of block
					if (tail_size == 0){	// When it didn't hash the block data yet.
						tail_size++;
						blake3(work_buf + slide_offset, block_size, buf_hash);

						// Count number of hashing.
						if (hash_counter == 0)
							hash_offset = slide_offset;
						hash_counter++;
						//printf("block[%I64u], hashing = %d, offset = %I64u + %I64u.\n", block_index, hash_counter, file_offset, slide_offset);
					}
					if (memcmp(buf_hash, block_list[block_index].hash, 16) == 0){
						slice_index = block_list[block_index].slice;
						if (par3_ctx->noise_level >= 3){
							printf("full block[%2I64d] : slice[%2I64d] offset = %I64u + %I64u\n",
									block_index, slice_index, file_offset, slide_offset);
						}
						if ((block_list[block_index].state & 4) == 0){	// When this block was not found yet.
							// Store filename & position of this slice for later reading.
							slice_list[slice_index].find_name = filename;
							slice_list[slice_index].find_offset = file_offset + slide_offset;
							block_list[block_index].state |= 4;
						}
						if (find_min > file_offset + slide_offset)
							find_min = file_offset + slide_offset;
						if (find_max < file_offset + slide_offset + block_size)
							find_max = file_offset + slide_offset + block_size;

						// Store offset of found block to check at first in next loop.
						if (next_offset == -1){
							next_offset = slide_offset;
							next_slice = slice_index;
						} else {
							next_offset = -2;
						}

						// When CRC and BLAKE3 match, remove this item from crc_list.
						if (find_index + 1 < crc_count)
							memmove(crc_list + find_index, crc_list + find_index + 1, sizeof(PAR3_CMP_CTX) * (crc_count - find_index - 1));
						crc_count--;
						// The same block won't be found in this file anymore.
						// It may be found in another damaged or extra file.
						//printf("Remove item[%I64d] : block[%I64u] from crc_list. crc_count = %I64u\n", find_index, block_index, crc_count);
						// If the block was found in another file already, find and remove the item again.

					} else {	// Goto next item
						find_index++;
					}

					if (find_index == crc_count)
						break;
					if (crc_list[find_index].crc != crc)
						break;
				}

				temp_crc = crc;	// Save previous CRC-64 to compare later
				crc = window_mask ^ crc_slide_byte(window_mask ^ crc,
						work_buf[slide_offset + block_size], work_buf[slide_offset], window_table);
				slide_offset++;

				if (hash_counter >= CHECK_SLIDE_INTERVAL){	// Check freeze after sliding several bytes each.
					// When hashing over than 8 times per 1 KB range.
					if (slide_offset - hash_offset <= ((uint64_t)CHECK_SLIDE_INTERVAL << CHECK_SLIDE_RANGE)){
						// When sliding over than time limit.
						if (clock() - time_slide >= time_limit){
							if (par3_ctx->noise_level >= 1){
								printf("Interrupt slide block by time out. offset = %I64u + %I64u.\n", file_offset, slide_offset);
							}
							flag_slide |= 1;
							break;
						}
					}
					hash_counter = 0;
					hash_offset = slide_offset;
				}
				if (crc == temp_crc){	// When CRC-64 is same after sliding 1 byte.
					if (tail_size == 0)
						blake3(work_buf + slide_offset - 1, block_size, buf_hash);
					blake3(work_buf + slide_offset, block_size, buf_hash2);
					if (memcmp(buf_hash, buf_hash2, 16) == 0){	// If BLAKE3 hash is same also, the data is uniform.
						uniform_start = slide_offset - 1;
						while ( (slide_offset < block_size) && (file_offset + slide_offset + block_size <= file_size)
								&& (crc == temp_crc) ){	// Skip the area of uniform data.
							crc = window_mask ^ crc_slide_byte(window_mask ^ crc,
									work_buf[slide_offset + block_size], work_buf[slide_offset], window_table);
							slide_offset++;
						}
						uniform_end = slide_offset;	// Offset of the last byte of uniform data
						if (par3_ctx->noise_level >= 3){
							printf("Because data is uniform, skip from %I64u to %I64u.\n", uniform_start, slide_offset);
						}
					}
				}
			}

			// When one block was found while sliding search.
			if (next_offset >= 0){
				if (slice_list[next_slice].next == -1){	// There is only one slice for the found block.
					slice_index = next_slice + 1;
					if (slice_index < slice_count){	// There is next slice
						if (slice_list[next_slice].chunk == slice_list[slice_index].chunk){	// Belong to same chunk
							next_slice = slice_index;
						} else {
							next_offset = -2;
						}
					} else {
						next_offset = -2;
					}
				} else {
					next_offset = -2;
				}
			}
		}

		// Compare current CRC-64 with chunk tails.
		if ( ((flag_slide & 4) == 0) && (tail_count > 0) && (file_offset + slide_start + 40 <= file_size) ){
			//printf("slide: offset = %I64u + %I64u, tail crc = 0x%016I64x\n", file_offset, slide_start, crc40);
			hash_counter = 0;
			hash_offset = 0;
			time_slide = clock();	// Store starting time of slide search.
			slide_offset = slide_start;
			while ( (slide_offset < block_size) && (file_offset + slide_offset + 40 <= file_size) ){
				// Because CRC-64 for chunk tails is a range of the first 40-bytes, total data may be different.
				tail_size = 0;
				// find_index is the first index of the matching CRC-64. There may be multiple items.
				find_index = cmp_list_search(par3_ctx, crc40, tail_list, tail_count);
				while (find_index >= 0){	// When CRC-64 is same.
					slice_index = tail_list[find_index].index;	// index of slice
					if (tail_size != slice_list[slice_index].size){
						tail_size = slice_list[slice_index].size;

						if ( (uniform_end > 0) && (slide_offset + tail_size < uniform_end + block_size) ){
							// Don't compare hash value, while uniform data.
							//printf("Skip slice[%I64u] in uniform data. offset = %I64u + %I64u.\n", slice_index, file_offset, slide_offset);
							memset(buf_hash, 0, 16);

						} else if (file_offset + slide_offset + tail_size <= file_size){
							blake3(work_buf + slide_offset, tail_size, buf_hash);

							// Count number of hashing.
							if (hash_counter == 0)
								hash_offset = slide_offset;
							hash_counter++;
							//printf("slice[%I64u], hashing = %d, offset = %I64u + %I64u.\n", slice_index, hash_counter, file_offset, slide_offset);

						} else {
							// When chunk tail exceeds file data, hash value becomes zero.
							memset(buf_hash, 0, 16);
						}
					}
					if (memcmp(buf_hash, chunk_list[slice_list[slice_index].chunk].tail_hash, 16) == 0){
						// When a chunk tail was found while slide search.
						block_index = slice_list[slice_index].block;
						if (par3_ctx->noise_level >= 3){
							printf("tail block[%2I64u] : slice[%2I64d] offset = %I64u + %I64u, tail size = %I64u, offset = %I64u\n",
									block_index, slice_index, file_offset, slide_offset, tail_size, slice_list[slice_index].tail_offset);
						}
						if (slice_list[slice_index].find_name == NULL){	// When this slice was not found yet.
							// Store filename & position of this slice for later reading.
							slice_list[slice_index].find_name = filename;
							slice_list[slice_index].find_offset = file_offset + slide_offset;
							block_list[block_index].state |= 8;
						}
						if (find_min > file_offset + slide_offset)
							find_min = file_offset + slide_offset;
						if (find_max < file_offset + slide_offset + tail_size)
							find_max = file_offset + slide_offset + tail_size;

						// When only one full size slice was found
						if (next_offset >= 0){
							if (slide_offset + tail_size > (uint64_t)next_offset)	// Check overlap of found slices
								next_offset = -2;
						}

						// When CRC and BLAKE3 match, remove this item from tail_list.
						if (find_index + 1 < tail_count)
							memmove(tail_list + find_index, tail_list + find_index + 1, sizeof(PAR3_CMP_CTX) * (tail_count - find_index - 1));
						tail_count--;
						//printf("Remove item[%I64d] : block[%I64u] from tail_list. tail_count = %I64u\n", find_index, block_index, tail_count);

					} else {	// Goto next item
						find_index++;
					}

					if (find_index == tail_count)
						break;
					if (tail_list[find_index].crc != crc40)
						break;
				}

				temp_crc = crc40;	// Save previous CRC-64 to compare later
				crc40 = window_mask40 ^ crc_slide_byte(window_mask40 ^ crc40,
						work_buf[slide_offset + 40], work_buf[slide_offset], window_table40);
				slide_offset++;

				if (hash_counter >= CHECK_SLIDE_INTERVAL){	// Check freeze after sliding several bytes each.
					// When hashing over than 8 times in 8 KB range. (average >= 1 time / 1 KB)
					if (slide_offset - hash_offset <= ((uint64_t)CHECK_SLIDE_INTERVAL << CHECK_SLIDE_RANGE)){
						// When sliding over than time limit.
						if (clock() - time_slide >= time_limit){
							if (par3_ctx->noise_level >= 1){
								printf("Interrupt slide tail by time out. offset = %I64u + %I64u.\n", file_offset, slide_offset);
							}
							flag_slide |= 2;
							break;
						}
					}
					hash_counter = 0;
					hash_offset = slide_offset;
				}
				if (crc40 == temp_crc){	// When CRC-64 is same after sliding 1 byte.
					// When offset is inside of uniform data.
					if ( (slide_offset >= uniform_start) && (slide_offset < uniform_end) ){
						// Skip the area of uniform data.
						slide_offset = uniform_end;
						if (par3_ctx->noise_level >= 3){
							printf("While data is uniform, skip from %I64u to %I64u.\n", uniform_start, uniform_end);
						}
						// No need to re-calculate CRC-64 after skip, because the value is same for uniform data.
						// Chunk tail is smaller than block size always.
					}
				}
			}
		}
		//printf("block crc = 0x%016I64x, tail crc = 0x%016I64x\n", crc, crc40);

		// Check range of found slices
		if ( (find_min < file_size) && (find_min > find_last) )
			damage_size += find_min - find_last;
		find_last = find_max;
		//printf("file_offset = %I64u, find_min = %I64u, find_max %I64u, damage_size = %I64u\n",
		//		file_offset, find_min, find_max, damage_size);

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


		// Only when skipping slide, calculate CRC-64 of next block.
		if ( ((flag_slide & 1) != 0) && (file_offset + block_size <= file_size) ){
			//printf("Calculate CRC-64 of next block.\n");
			crc = crc64(work_buf, block_size, 0);
		}
		if ( ((flag_slide & 2) != 0) && (file_offset + 40 <= file_size) ){
			//printf("Calculate CRC-64 of next tail.\n");
			crc40 = crc64(work_buf, 40, 0);
		}
	}

	// Check the last damaged area in this file
	if (find_max < file_size)
		damage_size += file_size - find_max;
	if (file_damage != NULL)
		*file_damage = damage_size;

	if (fclose(fp) != 0){
		perror("Failed to close input file");
		return RET_FILE_IO_ERROR;
	}

	// Calculate file hash to compare with misnamed files.
	if (file_hash != NULL)
		blake3_hasher_finalize(&hasher, file_hash, 16);

	return 0;
}

