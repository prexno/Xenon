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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s [new|load]\n", argv[0]);
    return 1;
  }

  if (strcmp("new", argv[1]) == 0) {
    const char *mnemonic[MNEMONIC_WORDS];
    uint16_t generated_salt = 0;

    if (create(mnemonic, &generated_salt) != EXIT_SUCCESS) {
      fprintf(stderr, "Failed to create mnemonic!\n");
      return -1;
    }

    printf("Mnemonic phrase (26 words):\n");
    for (int i = 0; i < MNEMONIC_WORDS; ++i) {
      printf("%s%s", mnemonic[i], (i == MNEMONIC_WORDS - 1) ? "" : " ");
    }
    putchar('\n');
    printf("Generated Salt (Hex): %04x\n", generated_salt);

  } else if (strcmp("load", argv[1]) == 0) {
    char input_buffer[MNEMONIC_WORDS][16];
    const char *mnemonic[MNEMONIC_WORDS];
    uint8_t entropy[ENTROPY_BYTES];
    uint16_t decoded_salt = 0;

    printf("Enter your 26-word mnemonic phrase:\n");
    for (int i = 0; i < MNEMONIC_WORDS; ++i) {
      if (scanf("%15s", input_buffer[i]) != 1) {
        fprintf(stderr, "Invalid input at word %d\n", i + 1);
        return -1;
      }
      mnemonic[i] = input_buffer[i];
    }

    if (load(mnemonic, entropy, &decoded_salt) != 0) {
      fprintf(stderr, "Mnemonic loading failed!\n");
      return -2;
    }

    printf("Decoded Entropy (Hex): ");
    for (int i = 0; i < ENTROPY_BYTES; ++i) {
      printf("%02x", entropy[i]);
    }
    putchar('\n');
    printf("Decoded Salt (Hex): %04x\n", decoded_salt);

    memset(entropy, 0, sizeof(entropy));
    memset(input_buffer, 0, sizeof(input_buffer));
  } else {
    fprintf(stderr, "Unknown command. Use 'new' or 'load'.\n");
    return 1;
  }

  return 0;
}
