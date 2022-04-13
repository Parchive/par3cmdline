
int check_input_directory(PAR3_CTX *par3_ctx, uint32_t *miss_dir_count);
int verify_input_file(PAR3_CTX *par3_ctx, uint32_t *lost_file_count, uint32_t *damaged_file_count);


// check input files
int check_complete_file(PAR3_CTX *par3_ctx, uint32_t file_id,
	uint64_t current_size, uint64_t *offset_next, uint64_t *find_slice);

int check_damaged_file(PAR3_CTX *par3_ctx, uint8_t *filename,
	uint64_t file_size, uint64_t file_offset, uint64_t *find_slice, uint8_t *file_hash);

