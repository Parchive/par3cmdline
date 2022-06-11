
// Create all recovery blocks from one input block.
void rs_create_one_all(PAR3_CTX *par3_ctx, int x_index);

// Create all recovery blocks from all input blocks.
void rs_create_all(PAR3_CTX *par3_ctx, size_t region_size);


// Construct matrix for Reed-Solomon, and solve linear equation.
int rs_compute_matrix(PAR3_CTX *par3_ctx, uint64_t lost_count);


// for 8-bit Cauchy Reed-Solomon
int rs8_gaussian_elimination(PAR3_CTX *par3_ctx, int lost_count);
int rs8_invert_matrix_cauchy(PAR3_CTX *par3_ctx, int lost_count);

// for 16-bit Cauchy Reed-Solomon
int rs16_gaussian_elimination(PAR3_CTX *par3_ctx, int lost_count);
int rs16_invert_matrix_cauchy(PAR3_CTX *par3_ctx, int lost_count);

