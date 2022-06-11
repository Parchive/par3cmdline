
// For 8-bit Galois Field
uint8_t * gf8_create_table(int prim_poly);

int gf8_multiply(uint8_t *galois_log_table, int x, int y);
int gf8_divide(uint8_t *galois_log_table, int x, int y);
int gf8_reciprocal(uint8_t *galois_log_table, int y);

void gf8_region_multiply(uint8_t *galois_log_table,
						uint8_t *region,	/* Region to multiply */
						int multby,			/* Number to multiply by */
						size_t nbytes,		/* Number of bytes in region */
						uint8_t *r2,		/* If r2 != NULL, products go here */
						int add);

void gf8_region_create_parity(int prim_poly, uint8_t *buf, size_t region_size, size_t data_size);
int gf8_region_check_parity(int galois_poly, uint8_t *buf, size_t region_size, size_t data_size);


// For 16-bit Galois Field
uint16_t * gf16_create_table(int prim_poly);

int gf16_multiply(uint16_t *galois_log_table, int x, int y);
int gf16_divide(uint16_t *galois_log_table, int x, int y);
int gf16_reciprocal(uint16_t *galois_log_table, int y);

void gf16_region_multiply(uint16_t *galois_log_table,
						uint8_t *region,	/* Region to multiply */
						int multby,			/* Number to multiply by */
						size_t nbytes,		/* Number of bytes in region */
						uint8_t *r2,		/* If r2 != NULL, products go here */
						int add);

void gf16_region_create_parity(int prim_poly, uint8_t *buf, size_t region_size, size_t data_size);
int gf16_region_check_parity(int galois_poly, uint8_t *buf, size_t region_size, size_t data_size);

