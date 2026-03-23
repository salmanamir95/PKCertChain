#ifndef BLOCK_H
#define BLOCK_H

#include "pkcertchain_config.h"


#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "datatype/uint256_t.h"
#include "datatype/uint512.h"
#include "blockchain/certificate.h"
#include "util/Size_Offsets.h"
#include "util/To_BO_BE_Pimitives.h"
#include "util/To_BO_Def_Primitives.h"
#include "datatype/OpStatus.h"

#define BLOCK_INLINE static inline __attribute__((always_inline))
#define BLOCK_SERIALIZED_SIZE BLOCK_SIZE

/*
 * PKCertChain Block
 * - Aligned 4 bytes (32-bit alignment)
 * - Uses fixed-width integers for determinism
 * - All serialization to network byte order
 */

typedef struct __attribute__((aligned(4)))
{
    certificate cert; // 68 bytes: pubSignKey + pubEncKey + id
    uint256 CurrentCertHash; // 32 bytes: hash of certificate
    uint256 prevHash; //32
    uint512 SignedByVerifier; // 64 bytes signature
    uint64_t height; //8
    uint64_t timestamp;   // 8 monotonic time, canonical 64-bit
} block;

BLOCK_INLINE void block_init(block *blk)
{
    cert_init(&blk->cert);
    uint256_zero(&blk->CurrentCertHash);
    uint256_zero(&blk->prevHash);
    uint512_zero(&blk->SignedByVerifier);
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

BLOCK_INLINE const uint256 *block_get_current_cert_hash(const block *blk)
{
    return &blk->CurrentCertHash;
}

BLOCK_INLINE const uint256 *block_get_prev_hash(const block *blk)
{
    return &blk->prevHash;
}

BLOCK_INLINE const uint512 *block_get_signed_by_verifier(const block *blk)
{
    return &blk->SignedByVerifier;
}

BLOCK_INLINE const uint64_t *block_get_height(const block *blk)
{
    return &blk->height;
}

BLOCK_INLINE void block_set_cert(block *blk, const certificate *cert)
{
    cert_copy(&blk->cert, cert);
}

BLOCK_INLINE void block_set_current_cert_hash(block *blk, const uint256 *current_cert_hash)
{
    memcpy(&blk->CurrentCertHash, current_cert_hash, UINT256_SIZE);
}

BLOCK_INLINE void block_set_timestamp(block *blk, uint64_t timestamp)
{
    blk->timestamp = timestamp;
}

BLOCK_INLINE void block_set_prev_hash(block *blk, const uint256 *prev_hash)
{
    memcpy(&blk->prevHash, prev_hash, UINT256_SIZE);
}

BLOCK_INLINE void block_set_signed_by_verifier(block *blk, const uint512 *signed_by_verifier)
{
    uint512_copy(&blk->SignedByVerifier, signed_by_verifier);
}

BLOCK_INLINE void block_set_height(block *blk, uint64_t height)
{
    blk->height = height;
}

BLOCK_INLINE void block_copy(block *dst, const block *src)
{
    cert_copy(&dst->cert, &src->cert);
    memcpy(&dst->CurrentCertHash, &src->CurrentCertHash, UINT256_SIZE);
    memcpy(&dst->prevHash, &src->prevHash, UINT256_SIZE);
    uint512_copy(&dst->SignedByVerifier, &src->SignedByVerifier);
    dst->height = src->height;
    dst->timestamp = src->timestamp;
}

BLOCK_INLINE OpStatus_t block_serialize(const block *blk, uint8_t *out, size_t out_size)
{
    if (!blk || !out) return OP_NULL_PTR;
    if (out_size < BLOCK_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    if (cert_serialize(&blk->cert, out, CERT_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint256_serialize_be(&blk->CurrentCertHash, out + CERT_SIZE, UINT256_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint256_serialize_be(&blk->prevHash, out + CERT_SIZE + UINT256_SIZE, UINT256_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint512_serialize_be(&blk->SignedByVerifier, out + CERT_SIZE + 2 * UINT256_SIZE, UINT512_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    serialize_u64_be(blk->height, out + CERT_SIZE + 2 * UINT256_SIZE + UINT512_SIZE);
    serialize_u64_be(blk->timestamp, out + CERT_SIZE + 2 * UINT256_SIZE + UINT512_SIZE + UINT64_SIZE);
    return OP_SUCCESS;
}

BLOCK_INLINE OpStatus_t block_deserialize(const uint8_t *in, size_t in_size, block *blk)
{
    if (!blk || !in) return OP_NULL_PTR;
    if (in_size < BLOCK_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    if (cert_deserialize(in, CERT_SIZE, &blk->cert) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint256_deserialize_be(in + CERT_SIZE, UINT256_SIZE, &blk->CurrentCertHash) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint256_deserialize_be(in + CERT_SIZE + UINT256_SIZE, UINT256_SIZE, &blk->prevHash) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint512_deserialize_be(in + CERT_SIZE + 2 * UINT256_SIZE, UINT512_SIZE, &blk->SignedByVerifier) != OP_SUCCESS) return OP_INVALID_INPUT;
    deserialize_u64_be(in + CERT_SIZE + 2 * UINT256_SIZE + UINT512_SIZE, &blk->height, sizeof(uint64_t));
    deserialize_u64_be(in + CERT_SIZE + 2 * UINT256_SIZE + UINT512_SIZE + UINT64_SIZE, &blk->timestamp, sizeof(uint64_t));
    return OP_SUCCESS;
}

#endif // BLOCK_H
