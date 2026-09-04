/*
    Xenon - a lightweight cryptographical tool with PQC by default
    Copyright (C) 2026 prexno

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

#include "bip39.h"
#include "wordlist.h"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

static int get_entropy_256(uint8_t entropy[ENTROPY_BYTES]) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return -1;

  size_t off = 0;
  while (off < ENTROPY_BYTES) {
    ssize_t n = read(fd, entropy + off, ENTROPY_BYTES - off);
    if (n > 0) {
      off += (size_t)n;
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else {
      close(fd);
      return -1;
    }
  }
  close(fd);
  return 0;
}

static int get_salt_16(uint16_t *salt) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    return -1;

  ssize_t n = read(fd, salt, sizeof(uint16_t));
  close(fd);
  return (n == sizeof(uint16_t)) ? 0 : -1;
}

static int bip39_checksum256(const uint8_t entropy[ENTROPY_BYTES],
                             uint8_t *checksum) {
  Sha256 sha;
  uint8_t hash[SHA256_DIGEST_SIZE];
  int ret;

  ret = wc_InitSha256(&sha);
  if (ret != 0)
    return ret;

  ret = wc_Sha256Update(&sha, entropy, ENTROPY_BYTES);
  if (ret != 0) {
    wc_Sha256Free(&sha);
    return ret;
  }

  ret = wc_Sha256Final(&sha, hash);
  if (ret != 0) {
    wc_Sha256Free(&sha);
    return ret;
  }
  *checksum = hash[0];

  memset(hash, 0, sizeof(hash));
  wc_Sha256Free(&sha);
  return 0;
}

int create(const char *mnemonic[MNEMONIC_WORDS], uint16_t *generated_salt) {
  uint8_t entropy[ENTROPY_BYTES];
  uint8_t checksum;
  uint16_t salt;

  uint8_t bits[38] = {0};

  if (get_entropy_256(entropy) != 0 || get_salt_16(&salt) != 0) {
    fprintf(stderr, "Failed to read /dev/urandom\n");
    return EXIT_FAILURE;
  }

  if (bip39_checksum256(entropy, &checksum) != 0) {
    fprintf(stderr, "SHA-256 failed\n");
    return EXIT_FAILURE;
  }

  *generated_salt = salt;

  memcpy(bits, entropy, ENTROPY_BYTES);
  bits[32] = checksum;
  bits[33] = (salt >> 8) & 0xFF;
  bits[34] = salt & 0xFF;

  for (int word = 0; word < MNEMONIC_WORDS; word++) {
    int bitpos = word * 11;
    int bytepos = bitpos / 8;
    int shift = bitpos % 8;

    uint32_t value = ((uint32_t)bits[bytepos] << 16) |
                     ((uint32_t)bits[bytepos + 1] << 8) |
                     ((uint32_t)bits[bytepos + 2]);

    int index = (value >> (24 - shift - 11)) & 0x7ff;
    mnemonic[word] = word_list[index];
  }

  memset(entropy, 0, sizeof(entropy));
  memset(bits, 0, sizeof(bits));
  return EXIT_SUCCESS;
}

static int find_word_index(const char *word) {
  for (int i = 0; i < 2048; ++i) {
    if (strcmp(word_list[i], word) == 0)
      return i;
  }
  return -1;
}

int load(const char *mnemonic[MNEMONIC_WORDS], uint8_t entropy[ENTROPY_BYTES],
         uint16_t *decoded_salt) {
  uint8_t bits[38] = {0};
  uint32_t bit_buffer = 0;
  int bits_in_buffer = 0;
  int byte_index = 0;

  for (int i = 0; i < MNEMONIC_WORDS; ++i) {
    int word_index = find_word_index(mnemonic[i]);
    if (word_index == -1) {
      fprintf(stderr, "Error: Word '%s' is not in the BIP39 wordlist.\n",
              mnemonic[i]);
      return -1;
    }
    bit_buffer = (bit_buffer << 11) | (uint32_t)word_index;
    bits_in_buffer += 11;

    while (bits_in_buffer >= 8) {
      bits_in_buffer -= 8;
      if (byte_index < 36) {
        bits[byte_index++] = (bit_buffer >> bits_in_buffer) & 0xFF;
      }
    }
  }
  memcpy(entropy, bits, ENTROPY_BYTES);
  *decoded_salt = ((uint16_t)bits[33] << 8) | bits[34];

  uint8_t expected_checksum;
  if (bip39_checksum256(entropy, &expected_checksum) != 0) {
    return -1;
  }

  if (bits[ENTROPY_BYTES] != expected_checksum) {
    fprintf(stderr,
            "Error: Checksum verification failed. Invalid mnemonic phrase.\n");
    return -1;
  }

  memset(bits, 0, sizeof(bits));
  return 0;
}
