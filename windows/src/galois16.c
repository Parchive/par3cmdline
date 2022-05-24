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
int * gf16_create_table(int prim_poly)
{
	int j, b;
	int *galois_log_table, *galois_ilog_table;

	// Allocate tables on memory
	galois_log_table = (int *) malloc(sizeof(int) * 65536 * 2);
	if (galois_log_table == NULL)
		return NULL;
	galois_ilog_table = galois_log_table + 65536;

	// galois_log_table[0] is invalid, because power of 2 never becomes 0.
	galois_log_table[0] = 65535;	// Instead of invalid value, set MAX value.
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
int gf16_multiply(int *galois_log_table, int x, int y)
{
	int sum_j;
	int *galois_ilog_table;

	if (x == 0 || y == 0)
		return 0;
	galois_ilog_table = galois_log_table + 65536;

	sum_j = galois_log_table[x] + galois_log_table[y];
	if (sum_j >= 65535)
		sum_j -= 65535;

	return galois_ilog_table[sum_j];
}

// Return (x / y)
int gf16_divide(int *galois_log_table, int x, int y)
{
	int sum_j;
	int *galois_ilog_table;

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
int gf16_reciprocal(int *galois_log_table, int y)
{
	int *galois_ilog_table;

	if (y == 0)
		return -1;	// Error: division by zero
	galois_ilog_table = galois_log_table + 65536;

	return galois_ilog_table[ 65535 - galois_log_table[y] ];
}


// Simplify and support size_t for 64-bit build
void gf16_region_multiply(int *galois_log_table,
						uint8_t *region,	/* Region to multiply */
						int multby,			/* Number to multiply by */
						size_t nbytes,		/* Number of bytes in region */
						uint8_t *r2,		/* If r2 != NULL, products go here */
						int add)
{
	uint16_t *ur1, *ur2;
	int prod, log1;
	size_t i;
	int *galois_ilog_table;

	ur1 = (uint16_t *) region;
	ur2 = (r2 == NULL) ? ur1 : (uint16_t *) r2;
	nbytes /= 2;	// Convert unit from byte to count.

	if (multby == 0) {
		if (add == 0){
			while (nbytes != 0){
				*ur2 = 0;
				ur2++;
				nbytes--;
			}
		}
		return;
	}

	galois_ilog_table = galois_log_table + 65536;
	log1 = galois_log_table[multby];

	if ( (r2 == NULL) || (add == 0) ) {
		for (i = 0; i < nbytes; i++) {
			if (ur1[i] == 0) {
				ur2[i] = 0;
			} else {
				prod = galois_log_table[ur1[i]] + log1;
				if (prod >= 65535)
					prod -= 65535;
				ur2[i] = galois_ilog_table[prod];
			}
		}

/*
	// XOR in 4 pack isn't so fast. No worth to do.
	} else if ( (((uintptr_t)ur2 & 7) == 0) && ((nbytes & 3) == 0) ) {
		// Data aligmnent is 8 bytes.
		int j;
		uint64_t *lp4, qw;	// quad word, 2 bytes * 4
		uint16_t *lp;

		lp4 = &qw;
		lp = (uint16_t *)lp4;
		for (i = 0; i < nbytes; i += 4) {
			lp4 = (uint64_t *)(ur2 + i);
			for (j = 0; j < 4; j++) {
				if (ur1[i + j] == 0) {
					lp[j] = 0;
				} else {
					prod = galois_log_table[ur1[i + j]] + log1;
					if (prod >= 65535)
						prod -= 65535;
					lp[j] = galois_ilog_table[prod];
				}
			}
			*lp4 = (*lp4) ^ qw;
		}
*/

	} else {
		for (i = 0; i < nbytes; i++) {
			if (ur1[i] != 0) {
				prod = galois_log_table[ur1[i]] + log1;
				if (prod >= 65535)
					prod -= 65535;
				ur2[i] ^= galois_ilog_table[prod];
			}
		}
	}
}

