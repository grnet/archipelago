/*
 * Copyright 2013 GRNET S.A. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 *   1. Redistributions of source code must retain the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and
 * documentation are those of the authors and should not be
 * interpreted as representing official policies, either expressed
 * or implied, of GRNET S.A.
 */

#include <hash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* hexlify function.
 * Unsafe. Doesn't check if data length is odd!
 */

void hexlify(unsigned char *data, long datalen, char *hex)
{
	long i;
	for (i=0; i<datalen; i++)
		sprintf(hex+2*i, "%02x", data[i]);
}

void unhexlify(char *hex, unsigned char *data)
{
	int i;
	char c;
	for (i=0; i<SHA256_DIGEST_LENGTH; i++){
		data[i] = 0;
		c = hex[2*i];
		if (isxdigit(c)){
			if (isdigit(c)){
				c-= '0';
			}
			else {
				c = tolower(c);
				c = c-'a' + 10;
			}
		}
		else {
			c = 0;
		}
		data[i] |= (c << 4) & 0xF0;
		c = hex[2*i+1];
		if (isxdigit(c)){
			if (isdigit(c)){
				c-= '0';
			}
			else {
				c = tolower(c);
				c = c-'a' + 10;
			}
		}
		else {
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

	if (!nr){
		SHA256(hashes, 0, hash);
		return;
	}
	if (nr == 1){
		memcpy(hash, hashes, SHA256_DIGEST_SIZE);
		return;
	}
	while (s < nr)
		s = s << 1;
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

