void hmac_md5(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void md5(uint8_t *buf, int len, uint8_t *out);
void md5_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void md5_hash_block(uint8_t *buf, uint32_t *hash);

void hmac_sha1(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha1(uint8_t *buf, int len, uint8_t *out);
void sha1_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha1_hash_block(uint8_t *buf, uint32_t *hash);

void hmac_sha224(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha224(uint8_t *buf, int len, uint8_t *out);
void sha224_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha224_hash_block(uint8_t *buf, uint32_t *hash);

void hmac_sha256(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha256(uint8_t *buf, int len, uint8_t *out);
void sha256_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha256_hash_block(uint8_t *buf, uint32_t *hash);

void hmac_sha384(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha384(uint8_t *buf, int len, uint8_t *out);
void sha384_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha384_hash_block(uint8_t *buf, uint64_t *hash);

void hmac_sha512(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha512(uint8_t *buf, int len, uint8_t *out);
void sha512_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha512_hash_block(uint8_t *buf, uint64_t *hash);
