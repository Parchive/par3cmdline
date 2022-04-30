
// For creation
int count_slice_info(PAR3_CTX *par3_ctx);
int set_slice_info(PAR3_CTX *par3_ctx);

int create_recovery_block(PAR3_CTX *par3_ctx);


// For verification
int find_identical_block(PAR3_CTX *par3_ctx);
uint64_t aggregate_input_block(PAR3_CTX *par3_ctx);

