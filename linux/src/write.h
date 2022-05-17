
void calculate_digit_max(PAR3_CTX *par3_ctx,
		uint64_t block_count, uint64_t first_num,
		uint64_t *p_base_num, uint64_t *p_max_count,
		int *p_digit_num1, int *p_digit_num2);


// for Create

int write_index_file(PAR3_CTX *par3_ctx);

int write_archive_file(PAR3_CTX *par3_ctx);

int write_recovery_file(PAR3_CTX *par3_ctx);


// for Trial

void try_index_file(PAR3_CTX *par3_ctx);

int try_archive_file(PAR3_CTX *par3_ctx);

int try_recovery_file(PAR3_CTX *par3_ctx);

