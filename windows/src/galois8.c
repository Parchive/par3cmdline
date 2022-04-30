// This is based on source code of Jerasure (v1.2), and modified for 8-bit Galois Field.

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
#include <stdio.h>
#include <stdlib.h>


// Create tables for 8-bit Galois Field
// Return main pointer of tables.
int * gf8_create_table(int prim_poly)
{
	int j, b;
	int x, y, logx, sum_j;
	int *galois_log_table, *galois_ilog_table, *galois_mult_table;

	// Allocate tables on memory
	galois_log_table = (int *) malloc(sizeof(int) * 256 * (1 + 1 + 256));
	if (galois_log_table == NULL)
		return NULL;
	galois_ilog_table = galois_log_table + 256;
	galois_mult_table = galois_log_table + 256 * 2;

	galois_log_table[0] = 255;	// galois_log_table[0] is invalid, because power of 2 never becomes 0.
	galois_ilog_table[255] = 1;	// 2 power 0 is 1. 2 power 255 is 1.

	b = 1;
	for (j = 0; j < 255; j++) {
		galois_log_table[b] = j;
		galois_ilog_table[j] = b;
		b = b << 1;
		if (b & 256)
			b = (b ^ prim_poly) & 255;
	}

	// Set multiply tables for x = 0
	j = 0;
	galois_mult_table[j] = 0;	// y = 0
	j++;
	for (y = 1; y < 256; y++){	// y > 0
		galois_mult_table[j] = 0;
		j++;
	}

	for (x = 1; x < 256; x++){	// x > 0
		galois_mult_table[j] = 0;	// y = 0
		j++;
		logx = galois_log_table[x];
		for (y = 1; y < 256; y++){	// y > 0
			sum_j = logx + galois_log_table[y];
			if (sum_j >= 255)
				sum_j -= 255;
			galois_mult_table[j] = galois_ilog_table[sum_j];
			j++;
		}
	}

	return galois_log_table;
}


// Return (x * y)
int gf8_multiply(int *galois_log_table, int x, int y)
{
	int sum_j;
	int *galois_ilog_table;

	if (x == 0 || y == 0)
		return 0;
	galois_ilog_table = galois_log_table + 256;

	sum_j = galois_log_table[x] + galois_log_table[y];
	if (sum_j >= 255)
		sum_j -= 255;

	return galois_ilog_table[sum_j];
}

// Using galois_mult_table
int gf8_fast_multiply(int *galois_log_table, int x, int y)
{
	int *galois_mult_table;

	galois_mult_table = galois_log_table + 256 * 2;

	return galois_mult_table[(x << 8) | y];
}

// Return (x / y)
int gf8_divide(int *galois_log_table, int x, int y)
{
	int sum_j;
	int *galois_ilog_table;

	if (y == 0)
		return -1;	// Error: division by zero
	if (x == 0)
		return 0;
	galois_ilog_table = galois_log_table + 256;

	sum_j = galois_log_table[x] - galois_log_table[y];
	if (sum_j < 0)
		sum_j += 255;

	return galois_ilog_table[sum_j];
}

// Return (1 / y)
int gf8_reciprocal(int *galois_log_table, int y)
{
	int *galois_ilog_table;

	if (y == 0)
		return -1;	// Error: division by zero
	galois_ilog_table = galois_log_table + 256;

	return galois_ilog_table[ 255 - galois_log_table[y] ];
}


void gf8_region_multiply(int *galois_log_table,
						char *region,		/* Region to multiply */
						int multby,			/* Number to multiply by */
						size_t nbytes,		/* Number of bytes in region */
						char *r2)			/* If r2 != NULL, products go here */
{
	unsigned char *ur1, *ur2, *cp;
	unsigned char prod;
	size_t i;
	int srow, j;
	int *galois_mult_table;
	size_t l, *lp2;
	unsigned char *lp;
	int sol;

	ur1 = (unsigned char *) region;
	ur2 = (r2 == NULL) ? ur1 : (unsigned char *) r2;

	galois_mult_table = galois_log_table + 256 * 2;
	srow = multby * 256;
	if (r2 == NULL) {
		for (i = 0; i < nbytes; i++) {
			prod = galois_mult_table[srow+ur1[i]];
			ur2[i] = prod;
		}
	} else {
		sol = sizeof(size_t);
		lp2 = &l;
		lp = (unsigned char *) lp2;
		for (i = 0; i < nbytes; i += sol) {
			cp = ur2+i;
			lp2 = (size_t *) cp;
			for (j = 0; j < sol; j++) {
				prod = galois_mult_table[srow+ur1[i+j]];
				lp[j] = prod;
			}
			*lp2 = (*lp2) ^ l;
		}
	}
}

