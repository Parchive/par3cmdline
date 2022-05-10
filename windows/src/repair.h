
uint32_t reconstruct_directory_tree(PAR3_CTX *par3_ctx);

int restore_input_file(PAR3_CTX *par3_ctx, char *temp_path);

int verify_repaired_file(PAR3_CTX *par3_ctx, char *temp_path,
		uint32_t *missing_file_count, uint32_t *damaged_file_count, uint32_t *misnamed_file_count);

