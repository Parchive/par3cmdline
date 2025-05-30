
uint32_t reconstruct_directory_tree(PAR3_CTX *par3_ctx);

// When there are enough input blocks after verification, no need Recovery Codes.
int create_temp_file(PAR3_CTX *par3_ctx, char *temp_path);
int restore_input_file(PAR3_CTX *par3_ctx, char *temp_path);

// For partial repair, when there are not enough blocks.
int try_restore_input_file(PAR3_CTX *par3_ctx, char *temp_path);

// Confirm input files after repair
int verify_repaired_file(PAR3_CTX *par3_ctx, char *temp_path,
		uint32_t *missing_file_count, uint32_t *damaged_file_count, uint32_t *misnamed_file_count, uint32_t *bad_file_count);

// Reset option of directories
uint32_t reset_directory_option(PAR3_CTX *par3_ctx);

