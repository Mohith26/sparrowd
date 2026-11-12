/* SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104). No heap, no dependencies. */
#ifndef SPARROW_SHA256_H
#define SPARROW_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LEN 32
#define SHA256_BLOCK_LEN 64

typedef struct {
    uint32_t h[8];
    uint64_t total_len;
    uint8_t buf[SHA256_BLOCK_LEN];
    size_t buf_len;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN]);
void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);

void hmac_sha256(const uint8_t *key, size_t key_len, const void *msg, size_t msg_len,
                 uint8_t out[SHA256_DIGEST_LEN]);

/* Constant-time comparison: returns 1 when equal. */
int ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

#endif
