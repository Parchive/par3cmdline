
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// MSVC headers
#include <search.h>

#include "blake3/blake3.h"
#include "libpar3.h"
#include "hash.h"


/*
CRC-64-ISO
https://reveng.sourceforge.io/crc-catalogue/17plus.htm

The Go Authors (26 January 2017), The Go Programming Language, module src/hash/crc64/crc64_test.go
https://go.dev/src/hash/crc64/crc64_test.go

#define CRC64_POLY	0xD800000000000000	// CRC-64-ISO (little endian)
*/

// Basic function, which calculates each byte.
/*
uint64_t crc64(const uint8_t *buf, size_t size, uint64_t crc)
{
	uint64_t A;

	crc = ~crc;
	for (size_t i = 0; i < size; ++i){
		A = crc ^ buf[i];
		A = A << 56;
		crc = (crc >> 8) ^ A ^ (A >> 1) ^ (A >> 3) ^ (A >> 4);
	}
	return ~crc;
}
*/

/*
Fast CRCs are from;
[1] Gam D. Nguyen, Fast CRCs, IEEE Transactions on Computers, vol. 58, no.
10, pp. 1321-1331, Oct. 2009.
*/

// Fast CRC function, which calculates 4 bytes per loop.
uint64_t crc64(const uint8_t *buf, size_t size, uint64_t crc)
{
	uint64_t A;

	crc = ~crc;	// bit flipping at first

	// calculate each byte until 4-bytes alignment
	while ((size > 0) && (((size_t)buf) & 3)){
		A = crc ^ (*buf++);
		A = A << 56;
		crc = (crc >> 8) ^ A ^ (A >> 1) ^ (A >> 3) ^ (A >> 4);
		size--;
	}

	// calculate 4-bytes per loop
	while (size >= 4){
		A = crc ^ (*((uint32_t *)buf));
		A = A << 32;

		// Below is same as this line;
		// crc = (crc >> 32) ^ A ^ (A >> 1) ^ (A >> 3) ^ (A >> 4);
		A = A ^ (A >> 1);
		crc = (crc >> 32) ^ A ^ (A >> 3);

		size -= 4;
		buf += 4;
	}

	// calculate remaining bytes
	while (size > 0){
		A = crc ^ (*buf++);
		A = A << 56;
		crc = (crc >> 8) ^ A ^ (A >> 1) ^ (A >> 3) ^ (A >> 4);
		size--;
	}

	return ~crc;	// bit flipping again
}

// This updates CRC-64 of zeros without bit flipping.
uint64_t crc64_update_zero(size_t size, uint64_t crc)
{
	uint64_t A;

	// calculate 4-bytes per loop
	while (size >= 4){
		A = crc << 32;

		// Below is same as this line;
		// crc = (crc >> 32) ^ A ^ (A >> 1) ^ (A >> 3) ^ (A >> 4);
		A = A ^ (A >> 1);
		crc = (crc >> 32) ^ A ^ (A >> 3);

		size -= 4;
	}

	while (size > 0){
		A = crc << 56;
		crc = (crc >> 8) ^ A ^ (A >> 1) ^ (A >> 3) ^ (A >> 4);
		size--;
	}

	return crc;
}

// This return window_mask.
static uint64_t init_slide_window(uint64_t window_size, uint64_t window_table[256])
{
	int i;
	uint64_t rr, window_mask;

	window_table[0] = 0; // This is always 0.
	for (i = 1; i < 256; i++){
		// calculate instant table of CRC-64-ISO
		rr = i;
		rr = rr << 56;
		rr = rr ^ (rr >> 1) ^ (rr >> 3) ^ (rr >> 4);
		window_table[i] = crc64_update_zero(window_size, rr);
	}

	window_mask = crc64_update_zero(window_size, ~0) ^ (~0);
	//printf("window_mask = 0x%016I64X, 0x%016I64X\n", window_mask, rr);

	return window_mask;
}

// table setup for slide window search
void init_crc_slide_table(PAR3_CTX *par3_ctx, int flag_usage)
{
	if (flag_usage & 1){
		// Creation needs block size only for deduplication.
		par3_ctx->window_mask = init_slide_window(par3_ctx->block_size, par3_ctx->window_table);
	}
	if (flag_usage & 2){
		// Verification needs 2 sizes for find blocks and chunk tails.
		par3_ctx->window_mask40 = init_slide_window(40, par3_ctx->window_table40);
	}
}

// Slide the CRC-64-ISO along a buffer by one byte (removing the old and adding the new).
// crc = window_mask ^ crc_slide_byte(window_mask ^ crc, buffer[window], buffer[0], window_table);
uint64_t crc_slide_byte(uint64_t crc, uint8_t byteNew, uint8_t byteOld, uint64_t window_table[256])
{
	uint64_t A;

	// CRC-64-ISO doesn't use table look-up.
	A = crc ^ byteNew;
	A = A << 56;
	crc = (crc >> 8) ^ A ^ (A >> 1) ^ (A >> 3) ^ (A >> 4);

	return crc ^ window_table[byteOld];
}


// Compare CRC-64 values
static int compare_crc( const void *arg1, const void *arg2 )
{
	PAR3_CMP_CTX *cmp1_p, *cmp2_p;

	cmp1_p = ( PAR3_CMP_CTX * ) arg1;
	cmp2_p = ( PAR3_CMP_CTX * ) arg2;

	if (cmp1_p->crc < cmp2_p->crc)
		return -1;
	if (cmp1_p->crc > cmp2_p->crc)
		return 1;

	return 0;
}

// Compare CRC-64 of blocks
// Return index of a block, which has the same CRC-64 and fingerprint hash.
// When no match, return -1 ~ -2. When fingerprint hash was calculated, return -3.
int64_t crc_list_compare(PAR3_CTX *par3_ctx, uint64_t crc, uint8_t *buf, uint8_t hash[16])
{
	uint64_t count, index;
	PAR3_CMP_CTX cmp_key, *cmp_p, *cmp2_p;
	PAR3_BLOCK_CTX *block_list;

	count = par3_ctx->crc_count;
	if (count == 0)
		return -1;

	// Binary search
	cmp_key.crc = crc;
	cmp_p = (PAR3_CMP_CTX *)bsearch( &cmp_key, par3_ctx->crc_list, (size_t)count, sizeof(PAR3_CMP_CTX), compare_crc );
	if (cmp_p == NULL)
		return -2;

	block_list = par3_ctx->block_list;
	blake3(buf, par3_ctx->block_size, hash);
	if (memcmp(hash, block_list[cmp_p->index].hash, 16) == 0)
		return cmp_p->index;

	// Search lower items of same CRC-64
	cmp2_p = cmp_p;
	index = cmp_p - par3_ctx->crc_list;
	while (index > 0){
		cmp2_p--;
		if (cmp2_p->crc != crc)
			break;
		if (memcmp(hash, block_list[cmp2_p->index].hash, 16) == 0)
			return cmp2_p->index;
		index--;
	}

	// Search higher items of same CRC-64
	cmp2_p = cmp_p;
	index = cmp_p - par3_ctx->crc_list;
	while (index + 1 < count){
		cmp2_p++;
		if (cmp2_p->crc != crc)
			break;
		if (memcmp(hash, block_list[cmp2_p->index].hash, 16) == 0)
			return cmp2_p->index;
		index++;
	}

	return -3;
}

// Add new crc in list and sort items.
void crc_list_add(PAR3_CTX *par3_ctx, uint64_t crc, uint64_t index)
{
	uint64_t count;

	count = par3_ctx->crc_count;

	// Add new item.
	par3_ctx->crc_list[count].crc = crc;
	par3_ctx->crc_list[count].index = index;
	count++;

	// Quick sort items.
	qsort( (void *)(par3_ctx->crc_list), (size_t)count, sizeof(PAR3_CMP_CTX), compare_crc );

	par3_ctx->crc_count = count;
}

// Make list of crc for seaching full size blocks and chunk tails.
int crc_list_make(PAR3_CTX *par3_ctx)
{
	uint64_t full_count, tail_count, index;
	uint64_t block_size, block_count, chunk_count, slice_count;
	PAR3_BLOCK_CTX *block_p;
	PAR3_CHUNK_CTX *chunk_list;
	PAR3_SLICE_CTX *slice_p;
	PAR3_CMP_CTX *crc_list, *tail_list;

	if (par3_ctx->block_count == 0){
		par3_ctx->crc_count = 0;
		par3_ctx->tail_count = 0;
		return 0;
	}

	// Allocate list of CRC-64 (double size for local copy)
	block_count = par3_ctx->block_count;
	crc_list = malloc(sizeof(PAR3_CMP_CTX) * block_count * 2);
	if (crc_list == NULL){
		perror("Failed to allocate memory for comparison of CRC-64");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->crc_list = crc_list;

	// At this time, number of tails is unknown.
	// When a chunk size is multiple of block size, the chunk has no tail.
	chunk_count = par3_ctx->chunk_count;
	tail_list = malloc(sizeof(PAR3_CMP_CTX) * chunk_count * 2);
	if (tail_list == NULL){
		perror("Failed to allocate memory for comparison of CRC-64");
		return RET_MEMORY_ERROR;
	}
	par3_ctx->tail_list = tail_list;

	full_count = 0;
	tail_count = 0;
	block_p = par3_ctx->block_list;
	chunk_list = par3_ctx->chunk_list;
	slice_count = par3_ctx->slice_count;
	slice_p = par3_ctx->slice_list;
	block_size = par3_ctx->block_size;

	// Find block of full size data, and set CRC of the block.
	for (index = 0; index < block_count; index++){
		// Even if checksum doesn't exist, the block is included.
		if (block_p->state & 1){
			crc_list[full_count].crc = block_p->crc;
			crc_list[full_count].index = index;
			full_count++;
		}

		block_p++;
	}

	// Find slice for chunk tail, and set CRC of the chunk.
	for (index = 0; index < slice_count; index++){
		if (slice_p->size < block_size){	// This slice is a chunk tail.
			tail_list[tail_count].crc = chunk_list[slice_p->chunk].tail_crc;
			tail_list[tail_count].index = index;
			tail_count++;
		}

		slice_p++;
	}

	// Re-allocate memory for actual number of CRC-64
	if (full_count < block_count){
		if (full_count > 0){
			crc_list = realloc(par3_ctx->crc_list, sizeof(PAR3_CMP_CTX) * full_count * 2);
			if (crc_list == NULL){
				perror("Failed to re-allocate memory for comparison of CRC-64");
				return RET_MEMORY_ERROR;
			}
			par3_ctx->crc_list = crc_list;
		} else {
			free(par3_ctx->crc_list);
			par3_ctx->crc_list = NULL;
		}
	}
	if (tail_count < chunk_count){
		if (tail_count > 0){
			tail_list = realloc(par3_ctx->tail_list, sizeof(PAR3_CMP_CTX) * tail_count * 2);
			if (tail_list == NULL){
				perror("Failed to re-allocate memory for comparison of CRC-64");
				return RET_MEMORY_ERROR;
			}
			par3_ctx->tail_list = tail_list;
		} else {
			free(par3_ctx->tail_list);
			par3_ctx->tail_list = NULL;
		}
	}

	// Quick sort items.
	if (full_count > 1){
		// CRC for full size block
		qsort( (void *)crc_list, (size_t)full_count, sizeof(PAR3_CMP_CTX), compare_crc );
	}
	if (tail_count > 1){
		// CRC for chunk tail
		qsort( (void *)tail_list, (size_t)tail_count, sizeof(PAR3_CMP_CTX), compare_crc );
	}

	par3_ctx->crc_count = full_count;
	par3_ctx->tail_count = tail_count;

	return 0;
}

// Replace crc of a block, and sort again.
void crc_list_replace(PAR3_CTX *par3_ctx, uint64_t crc, uint64_t index)
{
	int64_t i, count;
	PAR3_CMP_CTX *crc_list;

	if ( (par3_ctx->crc_list == NULL) || (par3_ctx->crc_count == 0) )
		return;

	crc_list = par3_ctx->crc_list;
	count = par3_ctx->crc_count;

	// Search the item and replace the value.
	for (i = 0; i < count; i++){
		if (crc_list[i].index == index){
			crc_list[i].crc = crc;
			i = -1;
			break;
		}
	}

	if ( (count > 1) && (i == -1) ){
		// Quick sort items.
		qsort( (void *)crc_list, (size_t)count, sizeof(PAR3_CMP_CTX), compare_crc );
	}
}

// Compare CRC-64 of blocks or chunk tails
// Return index of the first item, which has the same CRC-64.
// When no match, return -1 ~ -2
int64_t cmp_list_search(PAR3_CTX *par3_ctx, uint64_t crc, PAR3_CMP_CTX *cmp_list, int64_t count)
{
	int64_t index;
	PAR3_CMP_CTX cmp_key, *cmp_p;

	if (count == 0)
		return -1;

	// Binary search
	cmp_key.crc = crc;
	cmp_p = (PAR3_CMP_CTX *)bsearch( &cmp_key, cmp_list, (size_t)count, sizeof(PAR3_CMP_CTX), compare_crc );
	if (cmp_p == NULL)
		return -2;

	// Search lower items of same CRC-64
	index = cmp_p - cmp_list;
	while (index > 0){
		cmp_p--;
		if (cmp_p->crc != crc)
			break;
		index--;
	}

	return index;
}

// Compare CRC-64 of blocks or chunk tails
// When no match, return -1 ~ -3
int64_t cmp_list_search_index(PAR3_CTX *par3_ctx, uint64_t crc, int64_t id, PAR3_CMP_CTX *cmp_list, int64_t count)
{
	int64_t index;
	PAR3_CMP_CTX cmp_key, *cmp_p, *cmp2_p;

	if (count == 0)
		return -1;

	// Binary search
	cmp_key.crc = crc;
	cmp_p = (PAR3_CMP_CTX *)bsearch( &cmp_key, cmp_list, (size_t)count, sizeof(PAR3_CMP_CTX), compare_crc );
	if (cmp_p == NULL)
		return -2;

	// Search lower items of same CRC-64
	cmp2_p = cmp_p;
	index = cmp_p - cmp_list;
	if (cmp_p->index == id)
		return index;
	while (index > 0){
		cmp2_p--;
		if (cmp2_p->crc != crc)
			break;
		if (cmp2_p->index == id)
			return index;
		index--;
	}

	// Search higher items of same CRC-64
	cmp2_p = cmp_p;
	index = cmp_p - cmp_list;
	while (index + 1 < count){
		cmp2_p++;
		if (cmp2_p->crc != crc)
			break;
		if (cmp2_p->index == id)
			return index;
		index++;
	}

	return -3;
}


/*
This BLAKE3 code is non-SIMD subset of portable version from below;
https://github.com/BLAKE3-team/BLAKE3

The official C implementation of BLAKE3.

This work is released into the public domain with CC0 1.0. Alternatively, it is
licensed under the Apache License 2.0.
*/

// One time calculation, which returns 16-bytes hash value.
void blake3(const uint8_t *buf, size_t size, uint8_t *hash)
{
	// Initialize the hasher.
	blake3_hasher hasher;
	blake3_hasher_init(&hasher);

	blake3_hasher_update(&hasher, buf, size);

	// Finalize the hash.
	blake3_hasher_finalize(&hasher, hash, 16);
}


// Create parity bytes in the region
void region_create_parity(uint8_t *buf, size_t region_size, size_t data_size)
{
	size_t len;
	uint32_t sum;

	// When block size isn't multiple of 4, zero fill the last 1~3 bytes.
	if (data_size & 3){
		for (len = data_size; len < region_size - 4; len++){
			buf[len] = 0;
		}
	}

	// XOR all block data to 4 bytes
	len = data_size + 3;
	sum = 0;
	while (len >= 4){
		sum ^= *((uint32_t *)buf);

		len -= 4;
		buf += 4;
	}

	// Parity is 4 bytes.
	((uint32_t *)buf)[0] = sum;
}

// Check parity bytes in the region
int region_check_parity(uint8_t *buf, size_t region_size, size_t data_size)
{
	size_t len;
	uint32_t sum;

	// XOR all block data to 4 bytes
	len = data_size + 3;
	sum = 0;
	while (len >= 4){
		sum ^= *((uint32_t *)buf);

		len -= 4;
		buf += 4;
	}

	// Parity is 4 bytes.
	if (((uint32_t *)buf)[0] != sum)
		return 1;

	return 0;
}

