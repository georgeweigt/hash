/* This is a realization of MD5 and HMAC-MD5.

MD5 produces a 128-bit hash.

     128 bits = 16 bytes = 4 uint32_t

The main function of this program runs a self test.

To compile and run:

     gcc md5.c
     ./a.out

References

1. RFC 1321 The MD5 Message-Digest Algorithm

2. RFC 2104 HMAC: Keyed-Hashing for Message Authentication

BSD 2-Clause License

Copyright (c) 2016, George Weigt
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void hmac_md5(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void md5(uint8_t *buf, int len, uint8_t *out);
void md5_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void md5_hash_block(uint8_t *buf, uint32_t *hash);

int
main()
{
	int i;
	char s[33];
	uint8_t hash[16];

	md5((uint8_t *) "", 0, hash);

	for (i = 0; i < 16; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "d41d8cd98f00b204e9800998ecf8427e") == 0)
		puts("pass");
	else
		puts("fail");

	md5((uint8_t *) "message digest", 14, hash);

	for (i = 0; i < 16; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "f96b697d7cb7938d525a2f31aaf161d0") == 0)
		puts("pass");
	else
		puts("fail");

	hmac_md5((uint8_t *) "", 0, (uint8_t *) "", 0, hash);

	for (i = 0; i < 16; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "74e6f7298a9c2d168935f58c001bad88") == 0)
		puts("pass");
	else
		puts("fail");

	hmac_md5((uint8_t *) "key", 3, (uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);

	for (i = 0; i < 16; i++)
		sprintf(s + 2 * i, "%02x", ((uint8_t *) hash)[i]);

	if (strcmp(s, "80070713463e7749b90c2dc24911e275") == 0)
		puts("pass");
	else
		puts("fail");

	return 0;
}

void
hmac_md5(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out)
{
	int i;
	uint8_t pad[64], hash[16];

	memset(pad, 0, 64);

	// keys longer than 64 are hashed

	if (keylen > 64)
		md5(key, keylen, pad);
	else
		memcpy(pad, key, keylen);

	// xor ipad

	for (i = 0; i < 64; i++)
		pad[i] ^= 0x36;

	// hash

	md5_with_key(pad, buf, len, hash);

	// xor opad

	for (i = 0; i < 64; i++)
		pad[i] ^= 0x36 ^ 0x5c;

	// hash

	md5_with_key(pad, hash, 16, out);
}

void
md5(uint8_t *buf, int len, uint8_t *out)
{
	int i, n, r;
	uint8_t block[64];
	uint32_t hash[4];
	uint64_t m;

	n = len / 64;	// number of blocks
	r = len % 64;	// remainder bytes

	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;

	for (i = 0; i < n; i++) {
		md5_hash_block(buf, hash);
		buf += 64;
	}

	// depending on remainder, hash 1 or 2 more blocks

	memset(block, 0, 64);
	memcpy(block, buf, r);
	block[r] = 0x80;

	if (r >= 56) {
		md5_hash_block(block, hash);
		memset(block, 0, 64);
	}

	m = (uint64_t) 8 * len; // number of bits

	block[56] = m;
	block[57] = m >> 8;
	block[58] = m >> 16;
	block[59] = m >> 24;
	block[60] = m >> 32;
	block[61] = m >> 40;
	block[62] = m >> 48;
	block[63] = m >> 56;

	md5_hash_block(block, hash);

	for (i = 0; i < 4; i++) {
		out[4 * i + 0] = hash[i];
		out[4 * i + 1] = hash[i] >> 8;
		out[4 * i + 2] = hash[i] >> 16;
		out[4 * i + 3] = hash[i] >> 24;
	}
}

void
md5_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out)
{
	int i, n, r;
	uint8_t block[64];
	uint32_t hash[4];
	uint64_t m;

	n = len / 64;	// number of blocks
	r = len % 64;	// remainder bytes

	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;

	md5_hash_block(key, hash);

	for (i = 0; i < n; i++) {
		md5_hash_block(buf, hash);
		buf += 64;
	}

	// depending on remainder, hash 1 or 2 more blocks

	memset(block, 0, 64);
	memcpy(block, buf, r);
	block[r] = 0x80;

	if (r >= 56) {
		md5_hash_block(block, hash);
		memset(block, 0, 64);
	}

	m = (uint64_t) 8 * (len + 64); // number of bits

	block[56] = m;
	block[57] = m >> 8;
	block[58] = m >> 16;
	block[59] = m >> 24;
	block[60] = m >> 32;
	block[61] = m >> 40;
	block[62] = m >> 48;
	block[63] = m >> 56;

	md5_hash_block(block, hash);

	for (i = 0; i < 4; i++) {
		out[4 * i + 0] = hash[i];
		out[4 * i + 1] = hash[i] >> 8;
		out[4 * i + 2] = hash[i] >> 16;
		out[4 * i + 3] = hash[i] >> 24;
	}
}

static uint32_t s[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

static uint32_t K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

#define leftrotate(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

void
md5_hash_block(uint8_t *buf, uint32_t *hash)
{
	int i;
	uint32_t a, b, c, d, f, g, M, t;

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];

	for (i = 0; i < 16; i++) {
		f = (b & c) | (~b & d);
		t = d;
		d = c;
		c = b;
		M = buf[4 * i] | buf[4 * i + 1] << 8 | buf[4 * i + 2] << 16 | buf[4 * i + 3] << 24;
		b += leftrotate(a + f + K[i] + M, s[i]);
		a = t;
	}

	for (i = 16; i < 32; i++) {
		f = (d & b) | (~d & c);
		g = (5 * i + 1) & 0xf;
		t = d;
		d = c;
		c = b;
		M = buf[4 * g] | buf[4 * g + 1] << 8 | buf[4 * g + 2] << 16 | buf[4 * g + 3] << 24;
		b += leftrotate(a + f + K[i] + M, s[i]);
		a = t;
	}

	for (i = 32; i < 48; i++) {
		f = b ^ c ^ d;
		g = (3 * i + 5) & 0xf;
		t = d;
		d = c;
		c = b;
		M = buf[4 * g] | buf[4 * g + 1] << 8 | buf[4 * g + 2] << 16 | buf[4 * g + 3] << 24;
		b += leftrotate(a + f + K[i] + M, s[i]);
		a = t;
	}

	for (i = 48; i < 64; i++) {
		f = c ^ (b | ~d);
		g = (7 * i) & 0xf;
		t = d;
		d = c;
		c = b;
		M = buf[4 * g] | buf[4 * g + 1] << 8 | buf[4 * g + 2] << 16 | buf[4 * g + 3] << 24;
		b += leftrotate(a + f + K[i] + M, s[i]);
		a = t;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}
