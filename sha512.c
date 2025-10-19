/* This is a realization of SHA-512 and HMAC-SHA512.

SHA-512 produces a 512-bit hash.

     512 bits = 64 bytes = 8 uint64_t

The main function of this program runs a self test.

To compile and run:

     gcc sha512.c
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

void hmac_sha512(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha512(uint8_t *buf, int len, uint8_t *out);
void sha512_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha512_hash_block(uint8_t *buf, uint64_t *hash);

int
main()
{
	int i;
	char s[129];
	uint8_t hash[64];

	sha512((uint8_t *) "", 0, hash);

	for (i = 0; i < 64; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e") == 0)
		puts("pass");
	else
		puts("fail");

	sha512((uint8_t *) "abc", 3, hash);

	for (i = 0; i < 64; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") == 0)
		puts("pass");
	else
		puts("fail");

	puts("RFC 4231 Test Case 1");

	hmac_sha512((uint8_t *) "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, (uint8_t *) "Hi There", 8, hash);

	for (i = 0; i < 64; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854") == 0)
		puts("pass");
	else
		puts("fail");

	puts("RFC 4231 Test Case 2");

	hmac_sha512((uint8_t *) "Jefe", 4, (uint8_t *) "what do ya want for nothing?", 28, hash);

	for (i = 0; i < 64; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);

	if (strcmp(s, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737") == 0)
		puts("pass");
	else
		puts("fail");
}

void
hmac_sha512(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out)
{
	int i;
	uint8_t pad[128], hash[64];

	memset(pad, 0, 128);

	// keys longer than 128 are hashed

	if (keylen > 128)
		sha512(key, keylen, pad);
	else
		memcpy(pad, key, keylen);

	// xor ipad

	for (i = 0; i < 128; i++)
		pad[i] ^= 0x36;

	// hash

	sha512_with_key(pad, buf, len, hash);

	// xor opad

	for (i = 0; i < 128; i++)
		pad[i] ^= 0x36 ^ 0x5c;

	// hash

	sha512_with_key(pad, hash, 64, out);
}

void
sha512(uint8_t *buf, int len, uint8_t *out)
{
	int i, n, r;
	uint8_t block[128];
	uint64_t hash[8];
	uint64_t m;

	n = len / 128;	// number of blocks
	r = len % 128;	// remainder bytes

	hash[0] = 0x6a09e667f3bcc908ULL;
	hash[1] = 0xbb67ae8584caa73bULL;
	hash[2] = 0x3c6ef372fe94f82bULL;
	hash[3] = 0xa54ff53a5f1d36f1ULL;
	hash[4] = 0x510e527fade682d1ULL;
	hash[5] = 0x9b05688c2b3e6c1fULL;
	hash[6] = 0x1f83d9abfb41bd6bULL;
	hash[7] = 0x5be0cd19137e2179ULL;

	for (i = 0; i < n; i++) {
		sha512_hash_block(buf, hash);
		buf += 128;
	}

	// depending on remainder, hash 1 or 2 more blocks

	memset(block, 0, 128);
	memcpy(block, buf, r);
	block[r] = 0x80;

	if (r >= 120) {
		sha512_hash_block(block, hash);
		memset(block, 0, 128);
	}

	m = (uint64_t) 8 * len; // number of bits

	block[120] = m >> 56;
	block[121] = m >> 48;
	block[122] = m >> 40;
	block[123] = m >> 32;
	block[124] = m >> 24;
	block[125] = m >> 16;
	block[126] = m >> 8;
	block[127] = m;

	sha512_hash_block(block, hash);

	for (i = 0; i < 8; i++) {
		out[8 * i + 0] = hash[i] >> 56;
		out[8 * i + 1] = hash[i] >> 48;
		out[8 * i + 2] = hash[i] >> 40;
		out[8 * i + 3] = hash[i] >> 32;
		out[8 * i + 4] = hash[i] >> 24;
		out[8 * i + 5] = hash[i] >> 16;
		out[8 * i + 6] = hash[i] >> 8;
		out[8 * i + 7] = hash[i];
	}
}

void
sha512_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out)
{
	int i, n, r;
	uint8_t block[128];
	uint64_t hash[8];
	uint64_t m;

	n = len / 128;	// number of blocks
	r = len % 128;	// remainder bytes

	hash[0] = 0x6a09e667f3bcc908ULL;
	hash[1] = 0xbb67ae8584caa73bULL;
	hash[2] = 0x3c6ef372fe94f82bULL;
	hash[3] = 0xa54ff53a5f1d36f1ULL;
	hash[4] = 0x510e527fade682d1ULL;
	hash[5] = 0x9b05688c2b3e6c1fULL;
	hash[6] = 0x1f83d9abfb41bd6bULL;
	hash[7] = 0x5be0cd19137e2179ULL;

	sha512_hash_block(key, hash);

	for (i = 0; i < n; i++) {
		sha512_hash_block(buf, hash);
		buf += 128;
	}

	// depending on remainder, hash 1 or 2 more blocks

	memset(block, 0, 128);
	memcpy(block, buf, r);
	block[r] = 0x80;

	if (r >= 120) {
		sha512_hash_block(block, hash);
		memset(block, 0, 128);
	}

	m = (uint64_t) 8 * (len + 128); // number of bits

	block[120] = m >> 56;
	block[121] = m >> 48;
	block[122] = m >> 40;
	block[123] = m >> 32;
	block[124] = m >> 24;
	block[125] = m >> 16;
	block[126] = m >> 8;
	block[127] = m;

	sha512_hash_block(block, hash);

	for (i = 0; i < 8; i++) {
		out[8 * i + 0] = hash[i] >> 56;
		out[8 * i + 1] = hash[i] >> 48;
		out[8 * i + 2] = hash[i] >> 40;
		out[8 * i + 3] = hash[i] >> 32;
		out[8 * i + 4] = hash[i] >> 24;
		out[8 * i + 5] = hash[i] >> 16;
		out[8 * i + 6] = hash[i] >> 8;
		out[8 * i + 7] = hash[i];
	}
}

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROTR(n, x) (((x) >> (n)) | ((x) << (64 - (n))))

#define Sigma0(x) (ROTR(28, x) ^ ROTR(34, x) ^ ROTR(39, x))
#define Sigma1(x) (ROTR(14, x) ^ ROTR(18, x) ^ ROTR(41, x))

#define sigma0(x) (ROTR(1, x) ^ ROTR(8, x) ^ ((x) >> 7))
#define sigma1(x) (ROTR(19, x) ^ ROTR(61, x) ^ ((x) >> 6))

static uint64_t K[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

void
sha512_hash_block(uint8_t *buf, uint64_t *hash)
{
	int t;
	uint64_t a, b, c, d, e, f, g, h, T1, T2, W[80];

	for (t = 0; t < 16; t++) {
		W[t] = (uint64_t) buf[0] << 56 | (uint64_t) buf[1] << 48 | (uint64_t) buf[2] << 40 | (uint64_t) buf[3] << 32 | (uint64_t) buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7];
		buf += 8;
	}

	for (t = 16; t < 80; t++)
		W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];
	f = hash[5];
	g = hash[6];
	h = hash[7];

	for (t = 0; t < 80; t++) {
		T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
		T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
	hash[5] += f;
	hash[6] += g;
	hash[7] += h;
}
