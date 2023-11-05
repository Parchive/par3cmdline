#ifdef _WIN32
// avoid error of MSVC
#define _CRT_SECURE_NO_WARNINGS
#endif

/* Redefinition of _FILE_OFFSET_BITS must happen BEFORE including stdio.h */
#ifdef __linux__
#define _FILE_OFFSET_BITS 64
#define _stat64 stat
#elif _WIN32
#endif 


#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if __linux__

#warning "Assuming this Linux system uses 64-bit time."
/* There doesn't seem to be a preprocessor test for 64-bit time_t! 
   sizeof() is not available to the preprocessor.  */
/* NOTE: ctime is not threadsafe.  It returns a pointer to a static buffer.
   we should consider using ctime_r().  */
#define __time64_t int64_t
#define _ctime64 ctime

#include <sys/stat.h>

#elif _WIN32

// MSVC headers
#include <io.h>
#include <sys/stat.h>
#include <sys/utime.h>

#endif

#include "libpar3.h"
#include "packet.h"


/*
Converting a time_t value to a FILETIME
https://docs.microsoft.com/en-us/windows/win32/sysinfo/converting-a-time-t-value-to-a-file-time
*/
static uint64_t TimetToFileTime(uint64_t unix_time)
{
	uint64_t file_time;

	file_time = (unix_time * 10000000LL) + 116444736000000000LL;

	return file_time;
}

static uint64_t FileTimeToTimet(uint64_t file_time)
{
	uint64_t unix_time;

	unix_time = (file_time - 116444736000000000LL) / 10000000LL;

	return unix_time;
}


#if __linux__
#elif _WIN32

// File System Specific Packets (optional packets)
/*
https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/stat-functions?view=msvc-170
st_gid and st_uid are not supported on Windows OS.
st_atime may not be supported on Windows OS.
st_ctime has different property on Windows OS.

Bit of st_mode;
_S_IFDIR  = 0x4000, Directory
_S_IFREG  = 0x8000, Regular file
_S_IREAD  = 0x0100, Read permission, owner
_S_IWRITE = 0x0080, Write permission, owner
_S_IEXEC  = 0x0040, Execute/search permission, owner

At this time, it stores st_mtime and st_mode for compatibility.
*/

// UNIX Permissions Packet
// 0 = write ok, 1 = failed (no checksum)
// Return checksum of UNIX Permissions Packet in *checksum.
int make_unix_permission_packet(PAR3_CTX *par3_ctx, char *file_name, uint8_t *checksum)
{
	uint8_t pkt_buf[84];	// This is the minimum size of this packet.
	int ret;
	size_t packet_size;
	struct _stat64 stat_buf;

	// Store infomation, only when scuucess.
	if (_stat64(file_name, &stat_buf) != 0)
		return 1;

/*
	printf("Status information of \"%s\"\n", file_name);
	//printf("st_mtime = %016"PRIx64"\n", stat_buf.st_mtime);
	printf("st_mtime = %s", _ctime64(&(stat_buf.st_mtime)));
	printf("st_mode = 0x%04x\n\n", stat_buf.st_mode);
*/

	// It makes a packet on stack memory temporary.
	packet_size = 48;
	memset(pkt_buf + packet_size, 0xFF, 16);	// atime and ctime are not set.
	packet_size += 16;
	if (par3_ctx->file_system & 1){
		memcpy(pkt_buf + packet_size, &(stat_buf.st_mtime), 8);	// mtime
	} else {
		memset(pkt_buf + packet_size, 0xFF, 8);	// Default value when mtime isn't set.
	}
	packet_size += 8;
	memset(pkt_buf + packet_size, 0xFF, 8);	// owner UID and group GID are not set.
	packet_size += 8;
	if (par3_ctx->file_system & 2){
		ret = stat_buf.st_mode & 0x0FFF;	// lower 12-bit of i_mode
	} else {
		ret = 0xFFFF;	// When this item isn't used, store an invalid value.
	}
	memcpy(pkt_buf + packet_size, &ret, 2);
	packet_size += 2;
	memset(pkt_buf + packet_size, 0, 2);	// length of string (no names)
	packet_size += 2;
	// Packet size = 48 + 36 = 84
	make_packet_header(pkt_buf, packet_size, par3_ctx->set_id, "PAR UNX\0", 1);

	// Check existing packets if this packet was made already.
	ret = check_packet_exist(par3_ctx->file_system_packet, par3_ctx->file_system_packet_size, pkt_buf, packet_size);
	//printf("ret = %d, size = %zu\n", ret, par3_ctx->file_system_packet_size);
	if (ret == 0){
		memcpy(par3_ctx->file_system_packet + par3_ctx->file_system_packet_size, pkt_buf, packet_size);
		par3_ctx->file_system_packet_size += packet_size;
		par3_ctx->file_system_packet_count += 1;
	}

	// Write checksum of this packet
	memcpy(checksum, pkt_buf + 8, 16);

	return 0;
}

// FAT Permissions Packet
// 0 = write ok, 1 = failed (no checksum)
// Return checksum of FAT Permissions Packet in *checksum.
int make_fat_permission_packet(PAR3_CTX *par3_ctx, char *file_name, uint8_t *checksum)
{
	uint8_t pkt_buf[74];	// This is size of this packet.
	int ret;
	size_t packet_size;
	uint64_t file_time;
	struct _stat64 stat_buf;

	// Store infomation, only when scuucess.
	if (_stat64(file_name, &stat_buf) != 0)
		return 1;

/*
	printf("Status information of \"%s\"\n", file_name);
	printf("st_mtime = %s", _ctime64(&(stat_buf.st_mtime)));
*/

	// It makes a packet on stack memory temporary.
	packet_size = 48;
	memset(pkt_buf + packet_size, 0xFF, 16);	// CreationTimestamp and LastAccessTimestamp are not set.
	packet_size += 16;
	file_time = TimetToFileTime(stat_buf.st_mtime);	// Convert UNIX time to Windows FILETIME.
	memcpy(pkt_buf + packet_size, &file_time, 8);	// LastWriteTimestamp
	packet_size += 8;
	memset(pkt_buf + packet_size, 0xFF, 2);	// FileAttributes isn't set.
	packet_size += 2;
	// Packet size = 48 + 26 = 74
	make_packet_header(pkt_buf, packet_size, par3_ctx->set_id, "PAR FAT\0", 1);

	// Check existing packets if this packet was made already.
	ret = check_packet_exist(par3_ctx->file_system_packet, par3_ctx->file_system_packet_size, pkt_buf, packet_size);
	//printf("ret = %d, size = %zu\n", ret, par3_ctx->file_system_packet_size);
	if (ret == 0){
		memcpy(par3_ctx->file_system_packet + par3_ctx->file_system_packet_size, pkt_buf, packet_size);
		par3_ctx->file_system_packet_size += packet_size;
		par3_ctx->file_system_packet_count += 1;
	}

	// Write checksum of this packet
	memcpy(checksum, pkt_buf + 8, 16);

	return 0;
}
#endif

// For showing file list
static void show_file_system_info(PAR3_CTX *par3_ctx, uint8_t *checksum)
{
	uint8_t *packet_checksum, *packet_type, *buf;
	size_t offset, total_size;
	uint32_t item_value4;
	uint64_t packet_size;
	__time64_t item_value8;

	buf = par3_ctx->file_system_packet;
	total_size = par3_ctx->file_system_packet_size;

	offset = 0;
	while (offset + 48 < total_size){
		packet_checksum = buf + offset + 8;
		memcpy(&packet_size, buf + offset + 24, 8);
		packet_type = buf + offset + 40;

		if (memcmp(packet_checksum, checksum, 16) == 0){
			//printf("packet_size = %"PRIu64"\n", packet_size);
			if (memcmp(packet_type, "PAR UNX\0", 8) == 0){	// UNIX Permissions Packet
				if (par3_ctx->file_system & 3){
					printf("UNIX Permissions: ");
					if (par3_ctx->file_system & 2){	// i_mode
						item_value4 = 0;
						memcpy(&item_value4, buf + offset + 48 + 32, 2);
						if ((item_value4 & 0xF000) == 0){	// i_mode must be 12-bit value.
							printf("i_mode = 0x%03x", item_value4);
							if (par3_ctx->file_system & 1){
								printf(" , ");
							} else {
								printf("\n");
							}
						}
					}
					if (par3_ctx->file_system & 1){	// mtime
						memcpy(&item_value8, buf + offset + 48 + 16, 8);
						if (item_value8 != 0xFFFFFFFFFFFFFFFF){
							printf("mtime = %s", _ctime64(&item_value8));
						}
					}
				}

			} else if (memcmp(packet_type, "PAR FAT\0", 8) == 0){	// FAT Permissions Packet
				if (par3_ctx->file_system & 0x10000){
					printf("FAT Permissions: ");
					memcpy(&item_value8, buf + offset + 48 + 16, 8);
					if (item_value8 != 0xFFFFFFFFFFFFFFFF){
						item_value8 = FileTimeToTimet(item_value8);
						printf("LastWriteTime = %s", _ctime64(&item_value8));
					}
				}
			}
		}

		offset += packet_size;
	}
}

// packet_type: 1 = file, 2 = directory, 3 = root
void read_file_system_option(PAR3_CTX *par3_ctx, int packet_type, int64_t offset)
{
	uint8_t *tmp_p;
	int len;

	if (packet_type == 1){	// File Packet
		tmp_p = par3_ctx->file_packet;
		if (offset + 48 + 2 + 24 + 1 > (int64_t)(par3_ctx->file_packet_size))
			return;
		tmp_p += offset + 48;
		// Check name's length
		len = 0;
		memcpy(&len, tmp_p, 2);
		//printf("file name length = %d\n", len);
		if (offset + 48 + 2 + len + 24 + 1 > (int64_t)(par3_ctx->file_packet_size))
			return;
		tmp_p += 2 + len + 24;
		// Check options
		len = 0;
		memcpy(&len, tmp_p, 1);
		tmp_p += 1;

	} else if (packet_type == 2){	// Directory Packet
		tmp_p = par3_ctx->dir_packet;
		if (offset + 48 + 2 + 4 > (int64_t)(par3_ctx->dir_packet_size))
			return;
		tmp_p += offset + 48;
		// Check name's length
		len = 0;
		memcpy(&len, tmp_p, 2);
		//printf("dir name length = %d\n", len);
		if (offset + 48 + 2 + len + 4 > (int64_t)(par3_ctx->dir_packet_size))
			return;
		tmp_p += 2 + len;
		// Check options
		len = 0;
		memcpy(&len, tmp_p, 4);
		tmp_p += 4;

	} else {
		return;
	}
	//printf("number of options = %d\n", len);

	while (len > 0){
		show_file_system_info(par3_ctx, tmp_p);

		// Goto next option
		tmp_p += 16;
		len--;
	}
}


#if __linux__

#warning "static int check_file_system_info(PAR3_CTX *par3_ctx, uint8_t *checksum, void *stat_p) is UNDEFINED"

#elif _WIN32

// For verification
static int check_file_system_info(PAR3_CTX *par3_ctx, uint8_t *checksum, void *stat_p)
{
	uint8_t *packet_checksum, *packet_type, *buf;
	int ret;
	size_t offset, total_size;
	uint32_t item_value4;
	uint64_t packet_size;
	__time64_t item_value8;
	struct _stat64 *stat_buf;

	stat_buf = stat_p;
	//printf("i_mode = 0x%04x ", stat_buf->st_mode);
	//printf("mtime = %s", _ctime64(&(stat_buf->st_mtime)));

	buf = par3_ctx->file_system_packet;
	total_size = par3_ctx->file_system_packet_size;

	ret = 0;
	offset = 0;
	while (offset + 48 < total_size){
		packet_checksum = buf + offset + 8;
		memcpy(&packet_size, buf + offset + 24, 8);
		packet_type = buf + offset + 40;

		if (memcmp(packet_checksum, checksum, 16) == 0){
			//printf("packet_size = %"PRIu64"\n", packet_size);
			if (memcmp(packet_type, "PAR UNX\0", 8) == 0){	// UNIX Permissions Packet
				if (par3_ctx->file_system & 3){
					if (par3_ctx->file_system & 2){	// i_mode
						item_value4 = 0;
						memcpy(&item_value4, buf + offset + 48 + 32, 2);
						if ((item_value4 & 0xF000) == 0){	// i_mode must be 12-bit value.
							//printf("i_mode = 0x%04x\n", item_value4);
							if (item_value4 != (stat_buf->st_mode & 0x0FFF)){
								// Permission is different.
								ret |= 0x20000;
							}
						}
					}
					if (par3_ctx->file_system & 1){	// mtime
						memcpy(&item_value8, buf + offset + 48 + 16, 8);
						if (item_value8 != 0xFFFFFFFFFFFFFFFF){
							//printf("mtime = %s", _ctime64(&item_value8));
							if (item_value8 != stat_buf->st_mtime){
								// Timestamp is different.
								ret |= 0x10000;
							}
						}
					}
				}

			} else if (memcmp(packet_type, "PAR FAT\0", 8) == 0){	// FAT Permissions Packet
				if (par3_ctx->file_system & 0x10000){	// LastWriteTimestamp
					memcpy(&item_value8, buf + offset + 48 + 16, 8);
					if (item_value8 != 0xFFFFFFFFFFFFFFFF){
						item_value8 = FileTimeToTimet(item_value8);
						//printf("LastWriteTime = %s", _ctime64(&item_value8));
						if (item_value8 != stat_buf->st_mtime){
							// Timestamp is different.
							ret |= 0x10000;
						}
					}
				}
			}
		}

		offset += packet_size;
	}

	return ret;
}
#endif


// packet_type: 1 = file, 2 = directory, 3 = root
int check_file_system_option(PAR3_CTX *par3_ctx, int packet_type, int64_t offset, void *stat_p)
{
	uint8_t *tmp_p;
	int len, ret;

	if (packet_type == 1){	// File Packet
		tmp_p = par3_ctx->file_packet;
		if (offset + 48 + 2 + 24 + 1 > (int64_t)(par3_ctx->file_packet_size))
			return 0;
		tmp_p += offset + 48;
		// Check length of filename
		len = 0;
		memcpy(&len, tmp_p, 2);
		//printf("filename length = %d\n", len);
		if (offset + 48 + 2 + len + 24 + 1 > (int64_t)(par3_ctx->file_packet_size))
			return 0;
		tmp_p += 2 + len + 24;
		// Check options
		len = 0;
		memcpy(&len, tmp_p, 1);
		tmp_p += 1;

	} else if (packet_type == 2){	// Directory Packet
		tmp_p = par3_ctx->dir_packet;
		if (offset + 48 + 2 + 4 > (int64_t)(par3_ctx->dir_packet_size))
			return 0;
		tmp_p += offset + 48;
		// Check name's length
		len = 0;
		memcpy(&len, tmp_p, 2);
		//printf("dir name length = %d\n", len);
		if (offset + 48 + 2 + len + 4 > (int64_t)(par3_ctx->dir_packet_size))
			return 0;
		tmp_p += 2 + len;
		// Check options
		len = 0;
		memcpy(&len, tmp_p, 4);
		tmp_p += 4;

	} else {
		return 0;
	}
	//printf("number of options = %d\n", len);

	ret = 0;
	while (len > 0){
		ret |= check_file_system_info(par3_ctx, tmp_p, stat_p);

		// Goto next option
		tmp_p += 16;
		len--;
	}

	return ret;
}


#if __linux__

#warning "static int reset_file_system_info(PAR3_CTX *par3_ctx, uint8_t *checksum, char *file_name); is UNDEFINED"

#elif _WIN32

// For repair
static int reset_file_system_info(PAR3_CTX *par3_ctx, uint8_t *checksum, char *file_name)
{
	uint8_t *packet_checksum, *packet_type, *buf;
	int ret;
	size_t offset, total_size;
	uint32_t item_value4;
	uint64_t packet_size;
	__time64_t item_value8;
	struct _stat64 stat_buf;

	buf = par3_ctx->file_system_packet;
	total_size = par3_ctx->file_system_packet_size;

	ret = 0;
	offset = 0;
	while (offset + 48 < total_size){
		packet_checksum = buf + offset + 8;
		memcpy(&packet_size, buf + offset + 24, 8);
		packet_type = buf + offset + 40;

		if (memcmp(packet_checksum, checksum, 16) == 0){
			//printf("packet_size = %"PRIu64"\n", packet_size);
			if (memcmp(packet_type, "PAR UNX\0", 8) == 0){	// UNIX Permissions Packet
				// Recover infomation, only when scuucess.
				if (_stat64(file_name, &stat_buf) == 0){
					//printf("i_mode = 0x%04x ", stat_buf.st_mode);
					//printf("mtime = %s", _ctime64(&(stat_buf.st_mtime)));

					if (par3_ctx->file_system & 3){
						if (par3_ctx->file_system & 1){	// mtime
							memcpy(&item_value8, buf + offset + 48 + 16, 8);
							if (item_value8 != 0xFFFFFFFFFFFFFFFF){
								//printf("mtime = %s", _ctime64(&item_value8));
								if (item_value8 != stat_buf.st_mtime){	// Timestamp is different.
									struct _utimbuf ut;

									// When there is no write permission, set temporary.
									if ((stat_buf.st_mode & _S_IWRITE) == 0){
										if (_chmod(file_name, stat_buf.st_mode | _S_IWRITE) == 0){
											stat_buf.st_mode |= _S_IWRITE;
										}
									}

									// After get write permission, change timestamp.
									ut.actime = stat_buf.st_atime;	// Reuse current atime
									ut.modtime = item_value8;		// Recover to stored mtime
									if (_utime(file_name, &ut) != 0)
										ret |= 0x10000;	// Failed to reset timestamp
									// Caution ! this cannot modify directory on Windows OS.
								}
							}
						}
						if (par3_ctx->file_system & 2){	// i_mode
							item_value4 = 0;
							memcpy(&item_value4, buf + offset + 48 + 32, 2);
							if ((item_value4 & 0xF000) == 0){	// i_mode must be 12-bit value.
								if (item_value4 != (stat_buf.st_mode & 0x0FFF)){	// Permission is different.
									//printf("i_mode = 0x%04x, 0x%04x\n", item_value4, stat_buf.st_mode & 0x0FFF);
									if (_chmod(file_name, item_value4) != 0)
										ret |= 0x20000;	// Failed to reset permissions
								}
							}
						}
					}
				}

			} else if (memcmp(packet_type, "PAR FAT\0", 8) == 0){	// FAT Permissions Packet
				// Recover infomation, only when scuucess.
				if (_stat64(file_name, &stat_buf) == 0){
					//printf("mtime = %s", _ctime64(&(stat_buf.st_mtime)));

					if (par3_ctx->file_system & 0x10000){	// LastWriteTimestamp
						memcpy(&item_value8, buf + offset + 48 + 16, 8);
						if (item_value8 != 0xFFFFFFFFFFFFFFFF){
							item_value8 = FileTimeToTimet(item_value8);
							//printf("LastWriteTime = %s", _ctime64(&item_value8));
							if (item_value8 != stat_buf.st_mtime){	// Timestamp is different.
								struct _utimbuf ut;

								ut.actime = stat_buf.st_atime;	// Reuse current atime
								ut.modtime = item_value8;		// Recover to stored mtime
								if (_utime(file_name, &ut) != 0)
									ret |= 0x10000;	// Failed to reset timestamp
								// Caution ! UNIX time is low resolution than Windows FILETIME.
							}
						}
					}
				}
			}
		}

		offset += packet_size;
	}

	return ret;
}
#endif


// packet_type: 1 = file, 2 = directory, 3 = root
int test_file_system_option(PAR3_CTX *par3_ctx, int packet_type, int64_t offset, char *file_name)
{
	uint8_t *tmp_p;
	int len, ret;

	if (packet_type == 1){	// File Packet

		tmp_p = par3_ctx->file_packet;
		if (offset + 48 + 2 + 24 + 1 > (int64_t)(par3_ctx->file_packet_size))
			return 0;
		tmp_p += offset + 48;
		// Check length of filename
		len = 0;
		memcpy(&len, tmp_p, 2);
		//printf("filename length = %d\n", len);
		if (offset + 48 + 2 + len + 24 + 1 > (int64_t)(par3_ctx->file_packet_size))
			return 0;
		tmp_p += 2 + len + 24;
		// Check options
		len = 0;
		memcpy(&len, tmp_p, 1);
		tmp_p += 1;

	} else if (packet_type == 2){	// Directory Packet
		tmp_p = par3_ctx->dir_packet;
		if (offset + 48 + 2 + 4 > (int64_t)(par3_ctx->dir_packet_size))
			return 0;
		tmp_p += offset + 48;
		// Check name's length
		len = 0;
		memcpy(&len, tmp_p, 2);
		//printf("dir name length = %d\n", len);
		if (offset + 48 + 2 + len + 4 > (int64_t)(par3_ctx->dir_packet_size))
			return 0;
		tmp_p += 2 + len;
		// Check options
		len = 0;
		memcpy(&len, tmp_p, 4);
		tmp_p += 4;

	} else {
		return 0;
	}
	//printf("number of options = %d\n", len);

	ret = 0;
	while (len > 0){
		ret |= reset_file_system_info(par3_ctx, tmp_p, file_name);

		// Goto next option
		tmp_p += 16;
		len--;
	}

	return ret;
}

