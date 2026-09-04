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

#ifndef BIP39_H
#define BIP39_H

#include <stdint.h>
#define MNEMONIC_WORDS 26
#define ENTROPY_BYTES 32

int create(const char *mnemonic[MNEMONIC_WORDS], uint16_t *generated_salt);

int load(const char *mnemonic[MNEMONIC_WORDS], uint8_t entropy[ENTROPY_BYTES],
         uint16_t *decoded_salt);

#endif
