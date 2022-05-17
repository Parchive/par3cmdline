
int * gf8_create_table(int prim_poly);

int gf8_multiply(int *galois_log_table, int x, int y);
int gf8_fast_multiply(int *galois_log_table, int x, int y);

int gf8_divide(int *galois_log_table, int x, int y);
int gf8_reciprocal(int *galois_log_table, int y);

void gf8_region_multiply(int *galois_log_table,
						unsigned char *region,	/* Region to multiply */
						int multby,				/* Number to multiply by */
						size_t nbytes,			/* Number of bytes in region */
						unsigned char *r2,		/* If r2 != NULL, products go here */
						int add);

