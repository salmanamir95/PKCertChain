#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <endian.h> // htobe64
#include "datatype/uint256_t.h"
#include "blockchain/certificate.h"
#include "util/ser_primitives.h"

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
    certificate cert; // 96 bytes: pubSignKey + pubEncKey + id
    uint256 prevHash;
    uint64_t height;
    uint64_t timestamp;   // monotonic time, canonical 64-bit
} block;

BLOCK_INLINE void block_init(block *blk)
{
    cert_init(&blk->cert);
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
    dst->timestamp = src->timestamp;
}

BLOCK_INLINE OpStatus_t block_serialize(block *blk, uint8_t *buf, size_t buf_len)
{
    if (!blk || !buf)
        return OP_NULL_PTR;
    if (buf_len < BLOCK_SIZE)
        return OP_BUF_TOO_SMALL;

    // serialize certificate
    OpStatus_t status = cert_serialize(&blk->cert, buf, CERT_SIZE);
    if (status != OP_SUCCESS)
        return status;

    // serialize timestamp (big-endian)
    status = uint256_serialize(&blk->prevHash, buf + CERT_SIZE, UINT256_SIZE);
    if (status != OP_SUCCESS)
        return status;

    status = uint64_t_serialize(blk->height, buf + CERT_SIZE + UINT256_SIZE, UINT64_SIZE);
    if (status != OP_SUCCESS)
        return status;

    status = uint64_t_serialize(blk->timestamp, buf + CERT_SIZE + UINT256_SIZE + UINT64_SIZE, UINT64_SIZE);
    if (status != OP_SUCCESS)
        return status;

    return OP_SUCCESS;
}

BLOCK_INLINE OpStatus_t block_deserialize(block *blk, const uint8_t *buf, size_t buf_len)
{
    if (!blk || !buf)
        return OP_NULL_PTR;
    if (buf_len < BLOCK_SIZE)
        return OP_BUF_TOO_SMALL;

    // deserialize
    OpStatus_t status = cert_deserialize(&blk->cert, buf, CERT_SIZE);
    if (status != OP_SUCCESS)
        return status;

    status = uint256_deserialize(&blk->prevHash, buf + CERT_SIZE, UINT256_SIZE);
    if (status != OP_SUCCESS)
        return status;

    status = uint64_t_deserialize(&blk->height, buf + CERT_SIZE + UINT256_SIZE, UINT64_SIZE);
    if (status != OP_SUCCESS)
        return status;

    // deserialize timestamp
    status = uint64_t_deserialize(&blk->timestamp, buf + CERT_SIZE + UINT256_SIZE + UINT64_SIZE, UINT64_SIZE);

    return OP_SUCCESS;
}

#endif // BLOCK_H
