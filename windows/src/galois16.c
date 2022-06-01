// This is based on source code of Jerasure (v1.2), and modified for 16-bit Galois Field.

/* Galois.c
 * James S. Plank
 * April, 2007

Galois.tar - Fast Galois Field Arithmetic Library in C/C++
Copright (C) 2007 James S. Plank

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

James S. Plank
Department of Electrical Engineering and Computer Science
University of Tennessee
Knoxville, TN 37996
plank@cs.utk.edu

 */

// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>


// Create tables for 16-bit Galois Field
// Return main pointer of tables.
uint16_t * gf16_create_table(int prim_poly)
{
	int j, b;
	uint16_t *galois_log_table, *galois_ilog_table;

	// Allocate tables on memory
	// To fit CPU cache memory, table uses 16-bit integer.
	galois_log_table = malloc(sizeof(uint16_t) * 65536 * 2);
	if (galois_log_table == NULL)
		return NULL;
	galois_ilog_table = galois_log_table + 65536;

	// galois_log_table[0] is invalid, because power of 2 never becomes 0.
	galois_log_table[0] = prim_poly;	// Instead of invalid value, set generator polynomial.
	galois_ilog_table[65535] = 1;	// 2 power 0 is 1. 2 power 65535 is 1.

	b = 1;
	for (j = 0; j < 65535; j++) {
		galois_log_table[b] = j;
		galois_ilog_table[j] = b;
		b = b << 1;
		if (b & 65536)
			b = (b ^ prim_poly) & 65535;
	}

	return galois_log_table;
}


// Return (x * y)
int gf16_multiply(uint16_t *galois_log_table, int x, int y)
{
	int sum_j;
	uint16_t *galois_ilog_table;

	if (x == 0 || y == 0)
		return 0;
	galois_ilog_table = galois_log_table + 65536;

	sum_j = galois_log_table[x] + galois_log_table[y];
	if (sum_j >= 65535)
		sum_j -= 65535;

	return galois_ilog_table[sum_j];
}

// Return (x / y)
int gf16_divide(uint16_t *galois_log_table, int x, int y)
{
	int sum_j;
	uint16_t *galois_ilog_table;

	if (y == 0)
		return -1;	// Error: division by zero
	if (x == 0)
		return 0;
	galois_ilog_table = galois_log_table + 65536;

	sum_j = galois_log_table[x] - galois_log_table[y];
	if (sum_j < 0)
		sum_j += 65535;

	return galois_ilog_table[sum_j];
}

// Return (1 / y)
int gf16_reciprocal(uint16_t *galois_log_table, int y)
{
	uint16_t *galois_ilog_table;

	if (y == 0)
		return -1;	// Error: division by zero
	galois_ilog_table = galois_log_table + 65536;

	return galois_ilog_table[ 65535 - galois_log_table[y] ];
}


// This is based on GF-Complete, Revision 1.03.
// gf_w16_split_8_16_lazy_multiply_region

/*

Copyright (c) 2013, James S. Plank, Ethan L. Miller, Kevin M. Greenan,
Benjamin A. Arnold, John A. Burnum, Adam W. Disney, Allen C. McBride
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

 - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

 - Neither the name of the University of Tennessee nor the names of its
   contributors may be used to endorse or promote products derived
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/
void gf16_region_multiply(uint16_t *galois_log_table,
						uint8_t *region,	/* Region to multiply */
						int multby,			/* Number to multiply by */
						size_t nbytes,		/* Number of bytes in region */
						uint8_t *r2,		/* If r2 != NULL, products go here */
						int add)
{
	uint16_t *ur1, *ur2;
	int prod, v;
	size_t i;

	ur1 = (uint16_t *) region;
	ur2 = (r2 == NULL) ? ur1 : (uint16_t *) r2;
	nbytes /= 2;	// Convert unit from byte to count.

	if (multby == 0) {
		if (add == 0){
			for (i = 0; i < nbytes; i++) {
				ur2[i] = 0;
			}
		}

	} else if (multby == 1) {
		if (add == 0){
			if (r2 != NULL){
				for (i = 0; i < nbytes; i++) {
					ur2[i] = ur1[i];
				}
			}
		} else {
			if (r2 != NULL){
				for (i = 0; i < nbytes; i++) {
					ur2[i] ^= ur1[i];
				}
			} else {
				for (i = 0; i < nbytes; i++) {
					ur2[i] = 0;
				}
			}
		}

	// Use 8-bit split tables, only when nbytes is enough long.
	} else if (nbytes >= 1000){
		int j, k, prim_poly;
		uint16_t htable[256], ltable[256];

		// This table setup requires a bit time.
		prim_poly = galois_log_table[0] | 0x10000;
		v = multby;
		ltable[0] = 0;
		for (j = 1; j < 256; j <<= 1) {
			for (k = 0; k < j; k++)
				ltable[k^j] = (v ^ ltable[k]);

			// v = v * 2
			v = (v & (1 << 15)) ? ((v << 1) ^ prim_poly) : (v << 1);
		}
		htable[0] = 0;
		for (j = 1; j < 256; j <<= 1) {
			for (k = 0; k < j; k++)
				htable[k^j] = (v ^ htable[k]);

			// v = v * 2
			v = (v & (1 << 15)) ? ((v << 1) ^ prim_poly) : (v << 1);
		}

		if ( (r2 == NULL) || (add == 0) ) {
			for (i = 0; i < nbytes; i++) {
				v = ur1[i];
				if (v == 0) {
					ur2[i] = 0;
				} else {
				    prod = htable[v >> 8];
				    prod ^= ltable[v & 0xFF];
					ur2[i] = prod;
				}
			}
		} else {
			for (i = 0; i < nbytes; i++) {
				v = ur1[i];
				if (v != 0) {
				    prod = htable[v >> 8];
				    prod ^= ltable[v & 0xFF];
					ur2[i] ^= prod;
				}
			}
		}

	// Use Log & iLog tables
	} else {
		uint16_t *galois_ilog_table;

		galois_ilog_table = galois_log_table + 65536;
		v = galois_log_table[multby];

		if ( (r2 == NULL) || (add == 0) ) {
			for (i = 0; i < nbytes; i++) {
				if (ur1[i] == 0) {
					ur2[i] = 0;
				} else {
					prod = galois_log_table[ur1[i]] + v;
					if (prod >= 65535)
						prod -= 65535;
					ur2[i] = galois_ilog_table[prod];
				}
			}
		} else {
			for (i = 0; i < nbytes; i++) {
				if (ur1[i] != 0) {
					prod = galois_log_table[ur1[i]] + v;
					if (prod >= 65535)
						prod -= 65535;
					ur2[i] ^= galois_ilog_table[prod];
				}
			}
		}
	}
}


// Create parity bytes in the region
void gf16_region_create_parity(int prim_poly, uint8_t *buf, size_t region_size, size_t block_size)
{
	size_t len;
	uint32_t sum, temp, mask;

	prim_poly &= 0xFFFF;	// reduce to 16-bit value

	// When block size isn't multiple of 4, zero fill the last 1~3 bytes.
	if (block_size & 3){
		for (len = block_size; len < region_size - 4; len++){
			buf[len] = 0;
		}
	}

	// XOR all block data to 4 bytes
	len = block_size + 3;
	sum = 0;
	while (len >= 4){
		temp = *((uint32_t *)buf);

		// store highest bits of each 16-bit integer
		mask = (sum & 0x80008000) >> 15;	// 0x00010001 or 0x00000000

		// When SIMD is used, multiple of 2 is faster.
		// previous value multiply by 2
		//sum = (sum & 0x7FFF7FFF) << 1;

		// If multiple of 3 is good, it's possible by XOR to the original value.
		// previous value multiply by 3
		sum ^= (sum & 0x7FFF7FFF) << 1;

		// prim_poly may be 0x100B
		sum ^= mask * prim_poly;	// 0x100B100B or 0x00000000

	 	// add new 4 bytes
		sum ^= temp;

		len -= 4;
		buf += 4;
	}

	((uint32_t *)buf)[0] = sum;
}

// Check parity bytes in the region
int gf16_region_check_parity(int galois_poly, uint8_t *buf, size_t region_size, size_t block_size)
{
	size_t len;
	uint32_t sum, temp, mask;

	galois_poly &= 0xFFFF;	// reduce to 16-bit value

	// XOR all block data to 4 bytes
	len = block_size + 3;
	sum = 0;
	while (len >= 4){
		temp = *((uint32_t *)buf);

		// store highest bits of each 8-bit integer
		mask = (sum & 0x80008000) >> 15;	// 0x00010001 or 0x00000000

		// previous value multiply by 2
		//sum = (sum & 0x7FFF7FFF) << 1;

		// previous value multiply by 3
		sum ^= (sum & 0x7FFF7FFF) << 1;

		// galois_poly may be 0x100B
		sum ^= mask * galois_poly;	// 0x100B100B or 0x00000000

	 	// add new 4 bytes
		sum ^= temp;

		len -= 4;
		buf += 4;
	}

	// Parity is 4 bytes.
	if (((uint32_t *)buf)[0] != sum)
		return 1;

	return 0;
}

