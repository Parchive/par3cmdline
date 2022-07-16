
// File System Specific Packets

// UNIX Permissions Packet
int make_unix_permission_packet(PAR3_CTX *par3_ctx, char *file_name, uint8_t *checksum);

// For showing file list
void read_file_system_option(PAR3_CTX *par3_ctx, int64_t offset);

// For verification
int check_file_system_option(PAR3_CTX *par3_ctx, int64_t offset, void *stat_p);

// For repair
int test_file_system_option(PAR3_CTX *par3_ctx, int64_t offset, char *file_name);

