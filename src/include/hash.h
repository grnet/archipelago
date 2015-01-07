/*
Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <openssl/sha.h>
#include <ctype.h>

#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE 32
#endif
/* hex representation of sha256 value takes up double the sha256 size */
#define HEXLIFIED_SHA256_DIGEST_SIZE (SHA256_DIGEST_SIZE << 1)

/* hash helper functions tailored to SHA256 hash */
void hexlify(unsigned char *data, long datalen, char *hex);

void unhexlify(char *hex, unsigned char *data);

void merkle_hash(unsigned char *hashes, unsigned long len,
                 unsigned char hash[SHA256_DIGEST_SIZE]);
