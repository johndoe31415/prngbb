/*
	prngbb - PRNG bounded buffer writes for persistence atomicity analysis
	Copyright (C) 2023-2023 Johannes Bauer

	This file is part of prngbb.

	prngbb is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; this program is ONLY licensed under
	version 3 of the License, later versions are explicitly excluded.

	prngbb is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with prngbb; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	Johannes Bauer <JohannesBauer@gmx.de>
*/
// gcc -O2 -Wall -o prngbb-fill prngbb-fill.c -lcrypto && ./prngbb-fill /dev/zero 0 256 0 4096

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/evp.h>

/* This is absolutely not cryptographically sane, but we're essentially only
 * using AES-ECB as a glorified PRNG */
static void poor_mans_kdf(const char *seed, uint8_t key[static 16]) {
	if (!EVP_Digest(seed, strlen(seed), key, NULL, EVP_md5(), NULL)) {
		fprintf(stderr, "Failed: EVP_Digest\n");
		abort();
	}
}

static void block_set(uint8_t block[static 16], uint64_t ctr) {
	memset(block, 0, 16);
	*((uint64_t*)block) = ctr;
}

static double now(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec + 1e-6 * tv.tv_usec;
}

int main(int argc, char **argv) {
	if (argc != 6) {
		fprintf(stderr, "%s [filename] [seed] [chunk blocks] [offset] [bufsize in kiB]\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "Example: %s /dev/zero 0 256 0 40960\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	const char *filename = argv[1];
	const char *seed = argv[2];
	const char *chunk_blocks_str = argv[3];
	const char *offset = argv[4];
	const char *bufsize = argv[5];

	const unsigned int chunk_blocks = atoi(chunk_blocks_str);
	const unsigned int offset_bytes = atoi(offset);
	const unsigned int bufsize_bytes = atoi(bufsize) * 1024;
	uint8_t key[16];
	poor_mans_kdf(seed, key);

	printf("Offset %u bytes, bufsize %u bytes (%u kiB / %u MiB).\n", offset_bytes, bufsize_bytes, bufsize_bytes / 1024, bufsize_bytes / 1024 / 1024);
	printf("Executing a write() every %d AES blocks (%d bytes)\n", chunk_blocks, chunk_blocks * 16);
	if (bufsize_bytes % (chunk_blocks * 16)) {
		fprintf(stderr, "Fatal: buffer size not a multiple of chunk size.\n");
		exit(EXIT_FAILURE);
	}
	if (chunk_blocks < 1) {
		fprintf(stderr, "Fatal: illegal chunk_blocks value.\n");
		exit(EXIT_FAILURE);
	}
	const unsigned int block_count = bufsize_bytes / (16 * chunk_blocks);

	printf("Seed '%s' derived key: ", seed);
	for (int i = 0; i < 16; i++) {
		printf("%02x", key[i]);
	}
	printf("\n");

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed: EVP_CIPHER_CTX_new\n");
		abort();
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
		fprintf(stderr, "Failed: EVP_EncryptInit_ex\n");
		abort();
	}

	int fd = open(filename, O_WRONLY);
	if (fd == -1) {
		perror(filename);
		exit(EXIT_FAILURE);
	}

	const double t0 = now();
	bool first = true;
	uint64_t ctr = 0;
	unsigned int iteration = 1;
	while (true) {
		if (lseek(fd, offset_bytes, SEEK_SET) != offset_bytes) {
			perror("lseek");
			exit(EXIT_FAILURE);
		}

		for (unsigned int i = 0; i < block_count; i++) {
			uint8_t chunk[16 * chunk_blocks];
			for (unsigned int j = 0; j < chunk_blocks; j++) {
				ctr++;
				block_set(chunk + (16 * j), ctr);
			}

			int out_length = 0;
			if (EVP_EncryptUpdate(ctx, chunk, &out_length, chunk, 16 * chunk_blocks) != 1) {
				fprintf(stderr, "Failed: EVP_EncryptUpdate\n");
				abort();
			}
			if (out_length < 0) {
				fprintf(stderr, "Failed/negative out_length: EVP_EncryptUpdate\n");
				abort();
			}
			if ((unsigned int)out_length != 16 * chunk_blocks) {
				fprintf(stderr, "Failed/short encrypt: EVP_EncryptUpdate\n");
				abort();
			}
			if (write(fd, chunk, 16 * chunk_blocks) != 16 * chunk_blocks) {
				perror("write");
				abort();
			}
		}
		if (first) {
			const double t1 = now();
			printf("First chunk written in %.3f sec\n", t1 - t0);
			first = false;
		}
		printf("Iteration #%u sync.\n", iteration);
		fsync(fd);
		iteration++;
	}

	return 0;
}
