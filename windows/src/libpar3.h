#ifndef __LIBPAR3_H__
#define __LIBPAR3_H__


// Return value of par3cmdline (same as par2cmdline)
#define RET_SUCCESS             0

#define RET_REPAIR_POSSIBLE     1	// Data files are damaged and there is
									// enough recovery data available to repair them.

#define RET_REPAIR_NOT_POSSIBLE 2	// Data files are damaged and there is insufficient
									// recovery data available to be able to repair them.

#define RET_INVALID_COMMAND     3	// There was something wrong with the command line arguments

#define RET_INSUFFICIENT_DATA   4	// The PAR3 files did not contain sufficient information
									// about the data files to be able to verify them.

#define RET_REPAIR_FAILED       5	// Repair completed but the data files still appear to be damaged.

#define RET_FILE_IO_ERROR       6	// An error occurred when accessing files
#define RET_LOGIC_ERROR         7	// In internal error occurred
#define RET_MEMORY_ERROR        8	// Out of memory


typedef struct {
	uint64_t size;		// total size of chunk
	uint64_t block;		// index of first input block holding chunk

	uint64_t tail_crc;		// CRC-64 of first 40 bytes of tail
	uint8_t tail_hash[16];	// hash of all bytes of tail
	uint64_t tail_block;	// index of block holding tail
	uint64_t tail_offset;	// offset of tail inside block
} PAR3_CHUNK_CTX;

typedef struct {
	char *name;			// file name
	uint64_t size;		// file size
	uint64_t crc;		// CRC-64 of the first 16 KB
	uint8_t hash[16];	// BLAKE3 hash of the protected data

	uint32_t chunk;		// index of the first chunk
	uint32_t chunk_num;	// number of chunk descriptions
	uint64_t slice;		// index of the first slice

	uint64_t chk[2];	// checksum of File Packet
	int64_t offset;		// offset bytes of this File Packet

	uint32_t state;		// Result of verification (bit flag)
						// 1 = missing, 2 = damaged
						// 4 = misnamed, higher bit is (extra_id << 3).
						// 0x0100 = repaired, 0x0200 = repairable
						// 0x8000 = not file
} PAR3_FILE_CTX;

typedef struct {
	char *name;			// directory name
	uint64_t chk[2];	// checksum of Directory Packet
	int64_t offset;		// offset bytes of this Directory Packet
} PAR3_DIR_CTX;

typedef struct {
	uint32_t chunk;		// index of belong chunk description
	uint32_t file;		// index of belong input file
	int64_t offset;		// offset bytes of slice in belong input file
	uint64_t size;		// size of slice

	uint64_t block;			// index of input block holding this slice
	uint64_t tail_offset;	// offset bytes of the tail slice in belong block
	int64_t next;			// index of next slice in a same block

							// Result of verification
	char *find_name;		// filename of belong found file
	int64_t find_offset;	// offset bytes of found slice
} PAR3_SLICE_CTX;

typedef struct {
	int64_t slice;		// index of the first slice (in multiple slices)
	uint64_t size;		// data size in the block

	uint64_t crc;		// CRC-64-ISO
	uint8_t hash[16];	// BLAKE3 hash

	uint32_t state;	// bit flag: 1 = including full size data, 2 = including tail data
					// Result of verification
					// 4 = found full data, 8 = found tail data, 16 = found all tails
					// 64 = found checksum on External Data Packet
} PAR3_BLOCK_CTX;

typedef struct {
	uint64_t index;	// index of block
	uint64_t crc;	// CRC-64 of block
} PAR3_CMP_CTX;

typedef struct {
	uint64_t id;		// InputSetID
	uint8_t root[16];	// checksum from Root packet
	uint8_t matrix[16];	// checksum from Matrix packet

	uint64_t index;		// index of block
	char *name;			// name of belong file
	int64_t offset;		// offset bytes of packet
} PAR3_PKT_CTX;

typedef struct {
	uint64_t crc;		// CRC-64 of packet
	char *name;			// name of belong file
	int64_t offset;		// offset bytes of packet
} PAR3_POS_CTX;

typedef struct {
	// Command-line options
	int noise_level;
	char recovery_file_scheme;
	char deduplication;
	char data_packet;
	char absolute_path;
	uint32_t search_limit;	// how long time to slide search (milli second)
	uint64_t memory_limit;	// how much memory to use (byte)

	// For CRC-64 as rolling hash
	uint64_t window_table[256];		// slide window search for block size
	uint64_t window_mask;
	uint64_t window_table40[256];	// slide window search for the first 40-bytes of chunk tails
	uint64_t window_mask40;

	uint8_t *work_buf;		// Working buffer for temporary usage
	PAR3_CMP_CTX *crc_list;	// List of CRC-64 for slide window search
	uint64_t crc_count;		// Number of CRC-64 in the list
	PAR3_CMP_CTX *tail_list;
	uint64_t tail_count;

	uint8_t set_id[8];	// InputSetID
	uint8_t attribute;	// attributes in Root Packet
	uint8_t gf_size;	// The size of the Galois field in bytes

	int galois_poly;		// The generator polynomial of the Galois field
	void *galois_table;		// Pointer of tables for (finite) galois field arithmetic
	uint32_t ecc_method;	// Bit flag: 1 = Reed-Solomon Erasure Codes with Cauchy Matrix
							//           2 = Erasure Codes with Sparse Random Matrix (no support yet)
							//           4 = LDPC (no support yet)
							//           8 = FFT based Reed-Solomon Codes
							//      0x8000 = Keep all recovery blocks or lost blocks on memory

	int *recv_id_list;		// List for index of using recovery blocks
	void *matrix;

	uint64_t block_size;
	uint64_t block_count;		// This may be max or possible value at creating.
	PAR3_BLOCK_CTX *block_list;	// List of block information
	uint8_t *block_data;

	uint64_t first_recovery_block;
	uint64_t max_recovery_block;
	uint64_t recovery_block_count;
	uint32_t recovery_file_count;
	uint32_t redundancy_size;	// Lower 8-bit (0~250) is percent, or 251=KB, 252=MB, 253=GB.

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

	char *par_file_name;			// List of PAR3 file names
	size_t par_file_name_len;		// current used size
	size_t par_file_name_max;		// allocated size on memory

//	uint32_t extra_file_count;
	char *extra_file_name;			// List of extra file names
	size_t extra_file_name_len;		// current used size
	size_t extra_file_name_max;		// allocated size on memory

	uint32_t chunk_count;
	PAR3_CHUNK_CTX *chunk_list;		// List of chunk description
	uint64_t slice_count;
	PAR3_SLICE_CTX *slice_list;		// List of input file slice

	uint8_t *creator_packet;		// pointer to Creator Packet
	size_t creator_packet_size;		// size of Creator Packet
	uint32_t creator_packet_count;
	uint8_t *comment_packet;		// pointer to Comment Packet
	size_t comment_packet_size;		// size of Comment Packet
	uint32_t comment_packet_count;

	uint8_t *start_packet;			// pointer to Start Packet
	size_t start_packet_size;		// size of Start Packet
	uint32_t start_packet_count;
	uint8_t *matrix_packet;			// pointer to Matrix Packets
	size_t matrix_packet_size;		// total size of Matrix Packets
	uint32_t matrix_packet_count;
	size_t matrix_packet_offset;	// offset of using Matrix Packet for recovery

	uint8_t *file_packet;			// pointer to File Packets
	size_t file_packet_size;		// total size of File Packets
	uint32_t file_packet_count;
	uint8_t *dir_packet;			// pointer to Directory Packets
	size_t dir_packet_size;			// total size of Directory Packets
	uint32_t dir_packet_count;
	uint8_t *root_packet;			// pointer to Root Packet
	size_t root_packet_size;		// size of Root Packet
	uint32_t root_packet_count;

	uint8_t *ext_data_packet;		// pointer to External Data Packets
	size_t ext_data_packet_size;	// total size of External Data Packets
	uint32_t ext_data_packet_count;

	uint8_t *common_packet;			// pointer to duplicated common packets
	size_t common_packet_size;		// total size of duplicated common packets
	size_t common_packet_count;

	PAR3_POS_CTX *position_list;	// List of packet position
	PAR3_PKT_CTX *data_packet_list;	// List of Data Packets
	uint64_t data_packet_count;
	PAR3_PKT_CTX *recv_packet_list;	// List of Recovery Data Packets
	uint64_t recv_packet_count;

} PAR3_CTX;



// About input files
int path_search(PAR3_CTX *par3_ctx, char *match_path, int flag_recursive);
int get_file_status(PAR3_CTX *par3_ctx);
uint64_t suggest_block_size(PAR3_CTX *par3_ctx);
uint64_t calculate_block_count(PAR3_CTX *par3_ctx, uint64_t block_size);
int sort_input_set(PAR3_CTX *par3_ctx);


// Add text in Creator Packet or Comment Packet
int add_creator_text(PAR3_CTX *par3_ctx, char *text);
int add_comment_text(PAR3_CTX *par3_ctx, char *text);

// For creation
int par3_trial(PAR3_CTX *par3_ctx);
int par3_create(PAR3_CTX *par3_ctx);


// About par files
int par_search(PAR3_CTX *par3_ctx, int flag_other);
int extra_search(PAR3_CTX *par3_ctx, char *match_path);

// For verification and repair
int par3_list(PAR3_CTX *par3_ctx);
int par3_verify(PAR3_CTX *par3_ctx);
int par3_repair(PAR3_CTX *par3_ctx, char *temp_path);


// Release internal allocated memory
void par3_release(PAR3_CTX *par3_ctx);


#endif // __LIBPAR3_H__
