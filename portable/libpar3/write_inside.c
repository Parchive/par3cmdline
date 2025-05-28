#include "libpar3.h"

#include "../blake3/blake3.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "galois.h"
#include "hash.h"
#include "packet.h"
#include "write.h"


// Insert space into outside ZIP file
int insert_space_zip(PAR3_CTX *par3_ctx, int footer_size, int repeat_count)
{
	uint8_t *buf_p, *common_packet, packet_header[88];
	uint8_t gf_size;
	int galois_poly, ret;
	uint64_t block_count, block_index;
	uint64_t each_count, each_max;
	size_t block_size, region_size;
	size_t write_size;
	size_t common_packet_size;
	PAR3_POS_CTX *position_list;
	FILE *fp;
	blake3_hasher hasher;

	block_count = par3_ctx->recovery_block_count;
	block_size = par3_ctx->block_size;
	gf_size = par3_ctx->gf_size;
	galois_poly = par3_ctx->galois_poly;
	common_packet = par3_ctx->common_packet;
	common_packet_size = par3_ctx->common_packet_size;
	region_size = (block_size + 4 + 3) & ~3;
	buf_p = par3_ctx->block_data;

	// When recovery blocks were not created yet, allocate memory to store packet position.
	position_list = NULL;
	if ((par3_ctx->ecc_method & 0x8000) == 0){
		position_list = malloc(sizeof(PAR3_POS_CTX) * block_count);
		if (position_list == NULL){
			perror("Failed to allocate memory for position list");
			return RET_MEMORY_ERROR;
		}
		par3_ctx->position_list = position_list;
	}

	if (repeat_count <= 2){
		// Put mass of common packets in front & rear of Recovery Data
		// [ common packets ] [ Recovery data packets ] [ common packets ] [ Creator packet ]
		each_max = block_count;
	} else {
		// Insert mass of common packets between Recovery Data
		each_max = (block_count + repeat_count - 2) / (repeat_count - 1);
	}
	//printf("block_count = %"PRIu64", repeat_count = %d, each_max = %"PRIu64"\n", block_count, repeat_count, each_max);

	fp = fopen(par3_ctx->par_filename, "r+b");
	if (fp == NULL){
		perror("Failed to open Outside file");
		return RET_FILE_IO_ERROR;
	}

	// Put the first mass of common packets
	//printf("first common packets\n");
	if (_fseeki64(fp, 0, SEEK_END) != 0){
		perror("Failed to seek Outside file");
		fclose(fp);
		return RET_FILE_IO_ERROR;
	}
	write_size = common_packet_size;
	if (fwrite(common_packet, 1, write_size, fp) != write_size){
		perror("Failed to write first common packets on Outside file");
		fclose(fp);
		return RET_FILE_IO_ERROR;
	}

	// Common items in packet header of Recovery Data Packets
	memset(packet_header + 8, 0, 16);	// Zero fill checksum of packet as a sign of not calculated yet
	memcpy(packet_header + 48, par3_ctx->root_packet + 8, 16);	// The checksum from the Root packet
	memcpy(packet_header + 64, par3_ctx->matrix_packet + 8, 16);

	// Recovery Data Packet and repeated common packets
	each_count = 0;
	for (block_index = 0; block_index < block_count; block_index++){
		//printf("block_index = %"PRIu64"\n", block_index);

		// packet header
		make_packet_header(packet_header, 88 + block_size, par3_ctx->set_id, "PAR REC\0", 0);

		// The index of the recovery block
		memcpy(packet_header + 80, &block_index, 8);

		// When there is enough memory to keep all recovery blocks, recovery blocks were created already.
		if (par3_ctx->ecc_method & 0x8000){
			// Check parity of recovery block to confirm that calculation was correct.
			if (gf_size == 2){
				ret = gf16_region_check_parity(galois_poly, buf_p, region_size);
			} else if (gf_size == 1){
				ret = gf8_region_check_parity(galois_poly, buf_p, region_size);
			} else {
				ret = region_check_parity(buf_p, region_size);
			}
			if (ret != 0){
				printf("Parity of recovery block[%"PRIu64"] is different.\n", block_index);
				fclose(fp);
				return RET_LOGIC_ERROR;
			}

			// Calculate checksum of packet here.
			blake3_hasher_init(&hasher);
			blake3_hasher_update(&hasher, packet_header + 24, 24 + 40);
			blake3_hasher_update(&hasher, buf_p, block_size);
			blake3_hasher_finalize(&hasher, packet_header + 8, 16);

			// Write packet header and recovery data on file.
			if (fwrite(packet_header, 1, 88, fp) != 88){
				perror("Failed to write Recovery Data Packet on Outside file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			if (fwrite(buf_p, 1, block_size, fp) != block_size){
				perror("Failed to write Recovery Data Packet on Outside file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			buf_p += region_size;

		// When there isn't enough memory to keep all blocks, zero fill the block area.
		} else {
			// Save position of each recovery block for later wariting.
			position_list[block_index].name = par3_ctx->par_filename;
			position_list[block_index].offset = _ftelli64(fp);
			if (position_list[block_index].offset < 0){
				perror("Failed to get current position of Outside file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			//printf("block[%"PRIu64"] offset = %"PRId64", %s\n", block_index, position_list[block_index].offset, position_list[block_index].name);

			// Calculate CRC of packet data to check error, because state of BLAKE3 hash is too large.
			position_list[block_index].crc = crc64(packet_header + 24, 64, 0);

			// Write packet header and dummy data on file.
			if (fwrite(packet_header, 1, 88, fp) != 88){
				perror("Failed to write Recovery Data Packet on Outside file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			// Write zero bytes as dummy
			if (block_size > 1){
				if (_fseeki64(fp, block_size - 1, SEEK_CUR) != 0){
					perror("Failed to seek Outside file");
					fclose(fp);
					return RET_FILE_IO_ERROR;
				}
			}
			if (fwrite(packet_header + 8, 1, 1, fp) != 1){	// Write the last 1 byte of zero.
				perror("Failed to write Recovery Data Packet on Outside file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
		}

		// Put mass of common packets between Recovery Data Packets
		each_count++;
		if (each_count == each_max){
			//printf("common packets\n");
			write_size = common_packet_size;
			if (fwrite(common_packet, 1, write_size, fp) != write_size){
				perror("Failed to write common packets on Outside file");
				fclose(fp);
				return RET_FILE_IO_ERROR;
			}
			each_count = 0;
		}
	}

	// Put the last mass of common packets
	if (each_count > 0){
		//printf("last common packets\n");
		write_size = common_packet_size;
		if (fwrite(common_packet, 1, write_size, fp) != write_size){
			perror("Failed to write last common packets on Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// Creator Packet
	write_size = par3_ctx->creator_packet_size;
	if (write_size > 0){
		if (fwrite(par3_ctx->creator_packet, 1, write_size, fp) != write_size){
			perror("Failed to write Creator Packet on Outside file");
			fclose(fp);
			return RET_FILE_IO_ERROR;
		}
	}

	// Copy footer at the last
	if (footer_size > 0){
		buf_p = malloc(footer_size);
		if (buf_p == NULL){
			perror("Failed to allocate memory for footer");
			fclose(fp);
			return RET_MEMORY_ERROR;
		}

		// Read footer from the last of original ZIP file
		if (_fseeki64(fp, par3_ctx->total_file_size - footer_size, SEEK_SET) != 0){
			perror("Failed to seek Outside file");
			fclose(fp);
			free(buf_p);
			return RET_FILE_IO_ERROR;
		}
		if (fread(buf_p, 1, footer_size, fp) != footer_size){
			perror("Failed to read Outside file");
			fclose(fp);
			free(buf_p);
			return RET_FILE_IO_ERROR;
		}

		// Write footer at the last of outside ZIP file
		if (_fseeki64(fp, 0, SEEK_END) != 0){
			perror("Failed to seek Outside file");
			fclose(fp);
			free(buf_p);
			return RET_FILE_IO_ERROR;
		}
		if (fwrite(buf_p, 1, footer_size, fp) != footer_size){
			perror("Failed to write footer on Outside file");
			fclose(fp);
			free(buf_p);
			return RET_FILE_IO_ERROR;
		}

		free(buf_p);
	}

	if (fclose(fp) != 0){
		perror("Failed to close Outside file");
		return RET_FILE_IO_ERROR;
	}

	return 0;
}

