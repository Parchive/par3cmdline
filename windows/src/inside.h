
int check_outside_format(PAR3_CTX *par3_ctx, int *format_type, int *copy_size);
uint64_t inside_zip_size(PAR3_CTX *par3_ctx, uint64_t block_size, int footer_size,
			uint64_t *block_count, uint64_t *recv_block_count, int *packet_repeat_count);

