
// For creation
int count_slice_info(PAR3_CTX *par3_ctx);
int set_slice_info(PAR3_CTX *par3_ctx);

int allocate_recovery_block(PAR3_CTX *par3_ctx);
int create_recovery_block(PAR3_CTX *par3_ctx);
int create_recovery_block_split(PAR3_CTX *par3_ctx);
int create_recovery_block_cohort(PAR3_CTX *par3_ctx);


// For verification
int substitute_input_block(PAR3_CTX *par3_ctx);
int find_identical_block(PAR3_CTX *par3_ctx);
uint64_t aggregate_input_block(PAR3_CTX *par3_ctx);
uint64_t aggregate_recovery_block(PAR3_CTX *par3_ctx);
uint64_t aggregate_block_cohort(PAR3_CTX *par3_ctx, uint32_t *lost_count_cohort);
uint32_t check_possible_restore(PAR3_CTX *par3_ctx);


// For repair
int make_block_list(PAR3_CTX *par3_ctx, uint64_t lost_count, uint32_t lost_count_cohort);
int recover_lost_block(PAR3_CTX *par3_ctx, char *temp_path, int lost_count);
int recover_lost_block_split(PAR3_CTX *par3_ctx, char *temp_path, uint64_t lost_count);
int recover_lost_block_cohort(PAR3_CTX *par3_ctx, char *temp_path);

