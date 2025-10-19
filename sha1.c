/* This is a realization of SHA-1 and HMAC-SHA1.

SHA-1 produces a 160-bit hash.

     160 bits = 20 bytes = 5 uint32_t

The main function of this program runs a self test.

To compile and run:

     gcc sha1.c
     ./a.out

References

1. FIPS PUB 180-4, "Secure Hash Standard"

2. RFC 2104, "HMAC: Keyed-Hashing for Message Authentication"

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

void hmac_sha1(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha1(uint8_t *buf, int len, uint8_t *out);
void sha1_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha1_hash_block(uint8_t *buf, uint32_t *hash);

int
main()
{
	int i;
	char s[41];
	uint8_t hash[20];

	sha1((uint8_t *) "", 0, hash);

	for (i = 0; i < 20; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "da39a3ee5e6b4b0d3255bfef95601890afd80709") == 0)
		puts("pass");
	else
		puts("fail");

	sha1((uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);

	for (i = 0; i < 20; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") == 0)
		puts("pass");
	else
		puts("fail");

	hmac_sha1((uint8_t *) "", 0, (uint8_t *) "", 0, hash);

	for (i = 0; i < 20; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d") == 0)
		puts("pass");
	else
		puts("fail");

	hmac_sha1((uint8_t *) "key", 3, (uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);

	for (i = 0; i < 20; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9") == 0)
		puts("pass");
	else
		puts("fail");

	return 0;
}

void
hmac_sha1(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out)
{
	int i;
	uint8_t pad[64], hash[20];

	memset(pad, 0, 64);

	// keys longer than 64 are hashed

	if (keylen > 64)
		sha1(key, keylen, pad);
	else
		memcpy(pad, key, keylen);

	// xor ipad

	for (i = 0; i < 64; i++)
		pad[i] ^= 0x36;

	// hash

	sha1_with_key(pad, buf, len, hash);

	// xor opad

	for (i = 0; i < 64; i++)
		pad[i] ^= 0x36 ^ 0x5c;

	// hash

	sha1_with_key(pad, hash, 20, out);
}

void
sha1(uint8_t *buf, int len, uint8_t *out)
{
	int i, n, r;
	uint8_t block[64];
	uint32_t hash[5];
	uint64_t m;

	n = len / 64;	// number of blocks
	r = len % 64;	// remainder bytes

	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;
	hash[4] = 0xc3d2e1f0;

	for (i = 0; i < n; i++) {
		sha1_hash_block(buf, hash);
		buf += 64;
	}

	// depending on remainder, hash 1 or 2 more blocks

	memset(block, 0, 64);
	memcpy(block, buf, r);
	block[r] = 0x80;

	if (r >= 56) {
		sha1_hash_block(block, hash);
		memset(block, 0, 64);
	}

	m = (uint64_t) 8 * len; // number of bits

	block[56] = m >> 56;
	block[57] = m >> 48;
	block[58] = m >> 40;
	block[59] = m >> 32;
	block[60] = m >> 24;
	block[61] = m >> 16;
	block[62] = m >> 8;
	block[63] = m;

	sha1_hash_block(block, hash);

	for (i = 0; i < 5; i++) {
		out[4 * i + 0] = hash[i] >> 24;
		out[4 * i + 1] = hash[i] >> 16;
		out[4 * i + 2] = hash[i] >> 8;
		out[4 * i + 3] = hash[i];
	}
}

void
sha1_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out)
{
	int i, n, r;
	uint8_t block[64];
	uint32_t hash[5];
	uint64_t m;

	n = len / 64;	// number of blocks
	r = len % 64;	// remainder bytes

	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;
	hash[4] = 0xc3d2e1f0;

	sha1_hash_block(key, hash);

	for (i = 0; i < n; i++) {
		sha1_hash_block(buf, hash);
		buf += 64;
	}

	// depending on remainder, hash 1 or 2 more blocks

	memset(block, 0, 64);
	memcpy(block, buf, r);
	block[r] = 0x80;

	if (r >= 56) {
		sha1_hash_block(block, hash);
		memset(block, 0, 64);
	}

	m = (uint64_t) 8 * (len + 64); // number of bits

	block[56] = m >> 56;
	block[57] = m >> 48;
	block[58] = m >> 40;
	block[59] = m >> 32;
	block[60] = m >> 24;
	block[61] = m >> 16;
	block[62] = m >> 8;
	block[63] = m;

	sha1_hash_block(block, hash);

	for (i = 0; i < 5; i++) {
		out[4 * i + 0] = hash[i] >> 24;
		out[4 * i + 1] = hash[i] >> 16;
		out[4 * i + 2] = hash[i] >> 8;
		out[4 * i + 3] = hash[i];
	}
}

#define ROTL(n, x) ((x << n) | (x >> (32 - n)))

#define F1(x, y, z) ((x & y) ^ (~x & z))
#define F2(x, y, z) (x ^ y ^ z)
#define F3(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define F4(x, y, z) (x ^ y ^ z)

#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

void
sha1_hash_block(uint8_t *buf, uint32_t *hash)
{
	int t;
	uint32_t a, b, c, d, e, f, T, W[80];

	for (t = 0; t < 16; t++) {
		W[t] = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
		buf += 4;
	}

	for (t = 16; t < 80; t++) {
		T = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
		W[t] = ROTL(1, T);
	}

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];

	for (t = 0; t < 20; t++) {
		f = F1(b, c, d);
		T = ROTL(5, a) + f + e + K1 + W[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
	}

	for (t = 20; t < 40; t++) {
		f = F2(b, c, d);
		T = ROTL(5, a) + f + e + K2 + W[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
	}

	for (t = 40; t < 60; t++) {
		f = F3(b, c, d);
		T = ROTL(5, a) + f + e + K3 + W[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
	}

	for (t = 60; t < 80; t++) {
		f = F4(b, c, d);
		T = ROTL(5, a) + f + e + K4 + W[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
}
