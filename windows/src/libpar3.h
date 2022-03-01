#ifndef __LIBPAR3_H__
#define __LIBPAR3_H__


// Return value of par3cmdline (same as par2cmdline)
#define RET_SUCCESS             0

#define RET_REPAIR_POSSIBLE     1	// Data files are damaged and there is
									// enough recovery data available to repair them.

#define RET_REPAIR_NOT_POSSIBLE 2	// Data files are damaged and there is insufficient
									// recovery data available to be able to repair them.

#define RET_INVALID_COMMAND     3	// There was something wrong with the command line arguments

#define RET_INSUFFICIENT_DATA   4	// The PAR2 files did not contain sufficient information
									// about the data files to be able to verify them.

#define RET_REPAIR_FAILED       5	// Repair completed but the data files still appear to be damaged.

#define RET_FILE_IO_ERROR       6	// An error occurred when accessing files
#define RET_LOGIC_ERROR         7	// In internal error occurred
#define RET_MEMORY_ERROR        8	// Out of memory


typedef struct {
	uint64_t size;			// total size of chunk
	uint8_t hash[16];		// BLAKE3 hash of entire chunk
	uint64_t index;			// index of first input block holding chunk

	uint64_t tail_crc;		// CRC-64 of first 40 bytes of tail
	uint8_t tail_hash[16];	// hash of all bytes of tail
	uint64_t tail_block;	// index of block holding tail
	uint64_t tail_offset;	// offset of tail inside block

	uint32_t next;			// index of next chunk
} PAR3_CHUNK_CTX;

typedef struct {
	char *name;			// file name
	uint64_t size;		// file size
	uint64_t crc;		// CRC-64 of the first 16 KB

	uint32_t chunk;		// index of the first chunk
	uint64_t chk[2];	// checksum of File Packet
} PAR3_FILE_CTX;

typedef struct {
	char *name;			// directory name
	uint64_t chk[2];	// checksum of Directory Packet
} PAR3_DIR_CTX;

typedef struct {
	uint32_t chunk;		// index of belong chunk description
	uint32_t file;		// index of belong input file
	uint64_t offset;	// offset bytes of the mapped area in belong file
	uint64_t size;		// size of mapped area

	uint64_t block;			// index of input block holding mapped area
	uint64_t tail_offset;	// offset bytes of the mapped tail in belong block

	int64_t same;		// index of same map info
	uint64_t next;		// index of next map info for chunk tail
} PAR3_MAP_CTX;

typedef struct {
	uint64_t map;		// index of first map info

	uint64_t crc;		// CRC-64-ISO
	uint8_t hash[16];	// BLAKE3 hash
} PAR3_BLOCK_CTX;

typedef struct {
	uint64_t index;	// index of block
	uint64_t crc;	// CRC-64 of block
} PAR3_CMP_CTX;

typedef struct {
	int noise_level;
	uint8_t attribute;	// attributes in Root Packet

	uint64_t window_table[256];		// slide window search for block size
	uint64_t window_mask;
	uint64_t window_table16[256];	// slide window search for the first 16 KB of input files
	uint64_t window_mask16;
	uint64_t window_table40[256];	// slide window search for the first 40-bytes of chunk tails
	uint64_t window_mask40;

	uint8_t *work_buf;		// Working buffer to keep two blocks for slide window search
	PAR3_CMP_CTX *crc_list;	// List of CRC-64 for slide window search

	uint8_t set_id[8];	// InputSetID

	uint64_t block_size;
	uint64_t block_count;		// This may be max or possible value at creating.
	PAR3_BLOCK_CTX *block_list;	// List of block information
	uint8_t *input_block;		// When it can keep all input blocks on memory

	uint64_t first_recovery_block;
	uint64_t recovery_block_count;
	uint32_t recovery_file_count;

	char base_path[_MAX_PATH];
	char par_filename[_MAX_PATH];

	uint64_t total_file_size;
	uint64_t max_file_size;

	uint32_t input_file_count;
	PAR3_FILE_CTX *input_file_list;	// List of file information
	char *input_file_name;			// List of file names
	size_t input_file_name_len;		// current used size
	size_t input_file_name_max;		// allocated size on memory

	uint32_t input_dir_count;
	PAR3_DIR_CTX *input_dir_list;	// List of directory information
	char *input_dir_name;			// List of directory names
	size_t input_dir_name_len;		// current used size
	size_t input_dir_name_max;		// allocated size on memory

	uint32_t chunk_count;
	PAR3_CHUNK_CTX *chunk_list;		// List of chunk description
	uint64_t map_count;
	PAR3_MAP_CTX *map_list;			// List of mapping

	uint8_t *creator_packet;		// pointer to Creator Packet
	size_t creator_packet_size;		// size of Creator Packet
	uint8_t *comment_packet;		// pointer to Comment Packet
	size_t comment_packet_size;		// size of Comment Packet

	uint8_t start_packet[85];		// buffer of Start Packet
	size_t start_packet_size;		// size of Start Packet
	uint8_t *matrix_packet;			// pointer to Matrix Packets
	size_t matrix_packet_size;		// total size of Matrix Packets

	uint8_t *file_packet;			// pointer to File Packets
	size_t file_packet_size;		// total size of File Packets
	uint32_t file_packet_count;
	uint8_t *dir_packet;			// pointer to Directory Packets
	size_t dir_packet_size;			// total size of Directory Packets
	uint32_t dir_packet_count;
	uint8_t *root_packet;			// pointer to Root Packet
	size_t root_packet_size;		// size of Root Packet

	uint8_t *ext_data_packet;		// pointer to External Data Packets
	size_t ext_data_packet_size;	// total size of External Data Packets
	uint32_t ext_data_packet_count;

	uint8_t *common_packet;			// pointer to duplicated common packets
	size_t common_packet_size;		// total size of duplicated common packets
	size_t common_packet_count;

} PAR3_CTX;


// About input files
int path_search(PAR3_CTX *par3_ctx, char *match_path, int flag_recursive);
int get_file_status(PAR3_CTX *par3_ctx);
uint64_t suggest_block_size(PAR3_CTX *par3_ctx);
uint64_t calculate_block_count(PAR3_CTX *par3_ctx, uint64_t block_size);
int sort_input_set(PAR3_CTX *par3_ctx);

// add text in Creator Packet or Comment Packet
int add_creator_text(PAR3_CTX *par3_ctx, char *text);
int add_comment_text(PAR3_CTX *par3_ctx, char *text);


int par3_trial(PAR3_CTX *par3_ctx,
	char command_recovery_file_scheme,
	char command_data_packet,
	char command_deduplication);

int par3_create(PAR3_CTX *par3_ctx,
	char command_recovery_file_scheme,
	char command_data_packet,
	char command_deduplication);

// Release internal allocated memory
void par3_release(PAR3_CTX *par3_ctx);


#endif // __LIBPAR3_H__
