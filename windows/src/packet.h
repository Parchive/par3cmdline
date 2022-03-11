
// for creation

void make_packet_header(uint8_t *buf, uint64_t packet_size, uint8_t *set_id, uint8_t *packet_type, int flag_hash);

int make_start_packet(PAR3_CTX *par3_ctx);
int make_matrix_packet(PAR3_CTX *par3_ctx);
int make_file_packet(PAR3_CTX *par3_ctx);
int make_ext_data_packet(PAR3_CTX *par3_ctx);

int duplicate_common_packet(PAR3_CTX *par3_ctx);


// for verification
int add_found_packet(PAR3_CTX *par3_ctx, uint8_t *packet);
int check_packet_set(PAR3_CTX *par3_ctx);

int parse_vital_packet(PAR3_CTX *par3_ctx);

