#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "datatype/uint256_t.h"
#include "blockchain/certificate.h"

#if !defined(__linux__)
#error "This implementation is Linux optimized only"
#endif

#define BLOCK_INLINE static inline __attribute__((always_inline))

/*
 * PKCertChain Block
 * - Aligned 32 bytes for cache efficiency
 * - Uses fixed-width integers for determinism
 * - All serialization to network byte order
 */

typedef struct __attribute__((aligned(32)))
{
    certificate cert; // 68 bytes: pubSignKey + pubEncKey + id
    uint256 prevHash; //32
    uint64_t height; //16 
    uint64_t timestamp;   // monotonic time, canonical 64-bit
} block;

BLOCK_INLINE void block_init(block *blk)
{
    cert_init(&blk->cert);
    uint256_zero(&blk->prevHash);
    blk->height = 0;
    blk->timestamp = 0;
}

BLOCK_INLINE const certificate *block_get_cert_ptr(const block *blk)
{
    return &blk->cert;
}

BLOCK_INLINE const uint64_t block_get_timestamp(const block *blk)
{
    return blk->timestamp;
}

BLOCK_INLINE const uint256 *block_get_prev_hash(const block *blk)
{
    return &blk->prevHash;
}

BLOCK_INLINE const uint64_t *block_get_height(const block *blk)
{
    return &blk->height;
}

BLOCK_INLINE void block_set_cert(block *blk, const certificate *cert)
{
    cert_copy(&blk->cert, cert);
}

BLOCK_INLINE void block_set_timestamp(block *blk, uint64_t timestamp)
{
    blk->timestamp = timestamp;
}

BLOCK_INLINE void block_set_prev_hash(block *blk, const uint256 *prev_hash)
{
    memcpy(&blk->prevHash, prev_hash, UINT256_SIZE);
}

BLOCK_INLINE void block_set_height(block *blk, uint64_t height)
{
    blk->height = height;
}

BLOCK_INLINE void block_copy(block *dst, const block *src)
{
    cert_copy(&dst->cert, &src->cert);
    memcpy(&dst->prevHash, &src->prevHash, UINT256_SIZE);
    dst->height = src->height;
    dst->timestamp = src->timestamp;
}

#endif // BLOCK_H
