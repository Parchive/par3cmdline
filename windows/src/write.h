
void show_sizing_scheme(PAR3_CTX *par3_ctx,
		uint32_t file_count, uint64_t base_num, uint64_t max_count);

uint32_t calculate_digit_max(PAR3_CTX *par3_ctx,
		uint64_t header_size, uint64_t block_count, uint64_t first_num,
		uint64_t *p_base_num, uint64_t *p_max_count,
		int *p_digit_num1, int *p_digit_num2);

void remove_recovery_file(PAR3_CTX *par3_ctx);


// for Create

int write_index_file(PAR3_CTX *par3_ctx);

int write_archive_file(PAR3_CTX *par3_ctx);

int write_recovery_file(PAR3_CTX *par3_ctx);


// for Trial

uint64_t try_index_file(PAR3_CTX *par3_ctx);

int try_archive_file(PAR3_CTX *par3_ctx, uint64_t *recovery_file_size);

int try_recovery_file(PAR3_CTX *par3_ctx, uint64_t *recovery_file_size);

