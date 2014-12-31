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

#include <hash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char get_hex(unsigned int h)
{
	switch (h)
	{
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
			return h + '0';
		case 10:
			return 'a';
		case 11:
			return 'b';
		case 12:
			return 'c';
		case 13:
			return 'd';
		case 14:
			return 'e';
		case 15:
			return 'f';
	}
	/* not reachable */
	return '0';
}

/* hexlify function.
 * Unsafe. Doesn't check if data length is odd!
 */

void hexlify(unsigned char *data, long datalen, char *hex)
{
	long i;
	for (i = 0; i < datalen; i++) {
		hex[2 * i] = get_hex((data[i] & 0xF0) >> 4);
		hex[2 * i + 1] = get_hex(data[i] & 0x0F);
	}
}

void unhexlify(char *hex, unsigned char *data)
{
	int i;
	char c;
	for (i=0; i<SHA256_DIGEST_LENGTH; i++) {
		data[i] = 0;
		c = hex[2*i];
		if (isxdigit(c)) {
			if (isdigit(c)) {
				c-= '0';
			} else {
				c = tolower(c);
				c = c-'a' + 10;
			}
		} else {
			c = 0;
		}
		data[i] |= (c << 4) & 0xF0;
		c = hex[2*i+1];
		if (isxdigit(c)) {
			if (isdigit(c)) {
				c-= '0';
			} else {
				c = tolower(c);
				c = c-'a' + 10;
			}
		} else {
			c = 0;
		}
		data[i] |= c & 0x0F;
	}
}

void merkle_hash(unsigned char *hashes, unsigned long len,
		unsigned char hash[SHA256_DIGEST_SIZE])
{
	unsigned long i, l, s = 2;
	unsigned long nr = len/SHA256_DIGEST_SIZE;
	unsigned char *buf;
	unsigned char tmp_hash[SHA256_DIGEST_SIZE];

	if (!nr) {
		SHA256(hashes, 0, hash);
		return;
	}
	if (nr == 1) {
		memcpy(hash, hashes, SHA256_DIGEST_SIZE);
		return;
	}
	while (s < nr) {
		s = s << 1;
    }
	buf = malloc(sizeof(unsigned char)* SHA256_DIGEST_SIZE * s);
	memcpy(buf, hashes, nr * SHA256_DIGEST_SIZE);
	memset(buf + nr * SHA256_DIGEST_SIZE, 0, (s - nr) * SHA256_DIGEST_SIZE);
	for (l = s; l > 1; l = l/2) {
		for (i = 0; i < l; i += 2) {
			SHA256(buf + (i * SHA256_DIGEST_SIZE),
					2 * SHA256_DIGEST_SIZE, tmp_hash);
			memcpy(buf + (i/2 * SHA256_DIGEST_SIZE),
					tmp_hash, SHA256_DIGEST_SIZE);
		}
	}
	memcpy(hash, buf, SHA256_DIGEST_SIZE);
}
