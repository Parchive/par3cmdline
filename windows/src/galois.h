
// For 8-bit Galois Field

int * gf8_create_table(int prim_poly);

int gf8_multiply(int *galois_log_table, int x, int y);
int gf8_divide(int *galois_log_table, int x, int y);
int gf8_reciprocal(int *galois_log_table, int y);

void gf8_region_multiply(int *galois_log_table,
						uint8_t *region,	/* Region to multiply */
						int multby,			/* Number to multiply by */
						size_t nbytes,		/* Number of bytes in region */
						uint8_t *r2,		/* If r2 != NULL, products go here */
						int add);


// For 16-bit Galois Field

int * gf16_create_table(int prim_poly);

int gf16_multiply(int *galois_log_table, int x, int y);
int gf16_divide(int *galois_log_table, int x, int y);
int gf16_reciprocal(int *galois_log_table, int y);

void gf16_region_multiply(int *galois_log_table,
						uint8_t *region,	/* Region to multiply */
						int multby,			/* Number to multiply by */
						size_t nbytes,		/* Number of bytes in region */
						uint8_t *r2,		/* If r2 != NULL, products go here */
						int add);

