#ifndef BLOCK_H
#define BLOCK_H




#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "core/datatypes/uint256_t.h"
#include "core/datatypes/uint512.h"
#include "blockchain/certificate.h"
#include "core/enums/Tier.h"
#include "core/Global_Size_Offsets.h"
#include "net/NetworkSerialization.h"
#include "net/NetworkSerialization.h"
#include "core/enums/OpStatus.h"
#include "protocol/proofs/mini_pow/mini_pow_Result_t.h"
#include "Proofs/TierPoW/tierPoWResult.h"

#define BLOCK_INLINE static inline __attribute__((always_inline))
#define BLOCK_SERIALIZED_SIZE (BLOCK_SIZE + MINI_POW_RESULT_SERIALIZED_SIZE + TIER_POW_RESULT_SERIALIZED_SIZE)


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
    Tier_t tier; // 1 byte
    uint8_t reserved[3]; // padding
    MiniPowResult miniPowResult;
    TierPowResult tierPoWResult;
} block;

BLOCK_INLINE void block_init(block *blk)
{
    cert_init(&blk->cert);
    uint256_zero(&blk->CurrentCertHash);
    uint256_zero(&blk->prevHash);
    uint512_zero(&blk->SignedByVerifier);
    blk->height = 0;
    blk->timestamp = 0;
    blk->tier = TIER_INVALID;
    memset(blk->reserved, 0, sizeof(blk->reserved));
    minipowresult_init(&blk->miniPowResult);
    tierpowresult_init(&blk->tierPoWResult);
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

BLOCK_INLINE const Tier_t *block_get_tier(const block *blk)
{
    return &blk->tier;
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

BLOCK_INLINE void block_set_tier(block *blk, Tier_t tier)
{
    blk->tier = tier;
}

BLOCK_INLINE void block_copy(block *dst, const block *src)
{
    cert_copy(&dst->cert, &src->cert);
    memcpy(&dst->CurrentCertHash, &src->CurrentCertHash, UINT256_SIZE);
    memcpy(&dst->prevHash, &src->prevHash, UINT256_SIZE);
    uint512_copy(&dst->SignedByVerifier, &src->SignedByVerifier);
    dst->height = src->height;
    dst->timestamp = src->timestamp;
    dst->tier = src->tier;
    memcpy(dst->reserved, src->reserved, sizeof(dst->reserved));
    dst->miniPowResult = src->miniPowResult;
    dst->tierPoWResult = src->tierPoWResult;
}

/* Moved to NetworkSerialization.h */


/* Moved to NetworkSerialization.h */


#endif // BLOCK_H
