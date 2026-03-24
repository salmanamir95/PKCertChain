#ifndef TIER_POW_CHALLENGE_H
#define TIER_POW_CHALLENGE_H

#include "pkcertchain_config.h"

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "datatype/OpStatus.h"
#include "blockchain/block.h"
#include "datatype/uint256_t.h"
#include "util/SignUtils.h"
#include "util/To_BO_Def_Primitives.h"
#include "util/Size_Offsets.h"

#define TIER_POW_CHALLENGE_INLINE static inline __attribute__((always_inline))

#define TIER_POW_CHALLENGE_SERIALIZED_SIZE TIER_POW_CHALLENGE_SIZE

/*
 * tier_pow_challenge_t:
 *  - 4-byte aligned (32-bit alignment)
 *  - deterministic 256-bit challenge
 *  - complexity 0-255 bits
 *  - padding to keep size a 32-bit multiple
 */
typedef struct __attribute__((aligned(4))) {
    uint256 challenge;   // 32 bytes
    uint8_t complexity;  // 1 byte
    uint64_t challenge_id; // 8 bytes
    uint8_t reserved[3]; // padding to make 32-bit multiple
} tier_pow_challenge_t;

TIER_POW_CHALLENGE_INLINE void tier_pow_challenge_init(tier_pow_challenge_t *pow)
{
    uint256_zero(&pow->challenge);
    pow->complexity = 0;
    pow->challenge_id = 0;
    memset(pow->reserved, 0, sizeof(pow->reserved));
}

TIER_POW_CHALLENGE_INLINE const uint256* tier_pow_challenge_get_challenge(const tier_pow_challenge_t *pow)
{
    return &pow->challenge;
}

TIER_POW_CHALLENGE_INLINE const uint64_t* tier_pow_challenge_get_challenge_id(const tier_pow_challenge_t *pow)
{
    return &pow->challenge_id;
}

TIER_POW_CHALLENGE_INLINE const uint8_t tier_pow_challenge_get_complexity(const tier_pow_challenge_t *pow)
{
    return pow->complexity;
}

TIER_POW_CHALLENGE_INLINE void tier_pow_challenge_set_challenge(tier_pow_challenge_t *pow, const uint256 *challenge)
{
    uint256_copy(&pow->challenge, challenge);
}

TIER_POW_CHALLENGE_INLINE void tier_pow_challenge_set_complexity(tier_pow_challenge_t *pow, uint8_t complexity)
{
    pow->complexity = complexity;
}

TIER_POW_CHALLENGE_INLINE void tier_pow_challenge_set_challenge_id(tier_pow_challenge_t *pow, uint64_t id)
{
    pow->challenge_id = id;
}

TIER_POW_CHALLENGE_INLINE void tier_pow_challenge_copy(tier_pow_challenge_t *dst, const tier_pow_challenge_t *src)
{
    uint256_copy(&dst->challenge, &src->challenge);
    dst->complexity = src->complexity;
    dst->challenge_id = src->challenge_id;
    memset(dst->reserved, 0, sizeof(dst->reserved));
}

TIER_POW_CHALLENGE_INLINE OpStatus_t tier_pow_challenge_serialize(const tier_pow_challenge_t *pow,
                                                                  uint8_t *out,
                                                                  size_t out_size)
{
    if (!pow || !out) return OP_NULL_PTR;
    if (out_size < TIER_POW_CHALLENGE_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    if (uint256_serialize_be(&pow->challenge, out, UINT256_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    serialize_u8(pow->complexity, out + UINT256_SIZE);
    serialize_u64_be(pow->challenge_id, out + UINT256_SIZE + 1);
    memcpy(out + UINT256_SIZE + 1 + UINT64_SIZE, pow->reserved, sizeof(pow->reserved));
    return OP_SUCCESS;
}

TIER_POW_CHALLENGE_INLINE OpStatus_t tier_pow_challenge_deserialize(const uint8_t *in,
                                                                    size_t in_size,
                                                                    tier_pow_challenge_t *pow)
{
    if (!pow || !in) return OP_NULL_PTR;
    if (in_size < TIER_POW_CHALLENGE_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    if (uint256_deserialize_be(in, UINT256_SIZE, &pow->challenge) != OP_SUCCESS) return OP_INVALID_INPUT;
    pow->complexity = in[UINT256_SIZE];
    deserialize_u64_be(in + UINT256_SIZE + 1, &pow->challenge_id, sizeof(uint64_t));
    memcpy(pow->reserved, in + UINT256_SIZE + 1 + UINT64_SIZE, sizeof(pow->reserved));
    return OP_SUCCESS;
}

/*
 * Generate TierPoW challenge:
 *  - Computes SHA256 hash over the block struct
 *  - Uses hash256_buffer from SignUtils (zero-copy)
 *  - Returns tier_pow_challenge_t with challenge and specified complexity
 */
TIER_POW_CHALLENGE_INLINE OpStatus_t generate_tier_pow_challenge(block *blk,
                                                                 uint8_t complexity,
                                                                 tier_pow_challenge_t *pow)
{
    uint8_t buf[CERT_SIZE + UINT256_SIZE + UINT64_SIZE + UINT64_SIZE + 4 * UINT8_SIZE];
    const size_t packed_len = sizeof(buf);

    if (!blk || !pow) return OP_NULL_PTR;

    uint256_serialize_be(&blk->cert.pubSignKey, buf, UINT256_SIZE);
    uint256_serialize_be(&blk->cert.pubEncKey, buf + UINT256_SIZE, UINT256_SIZE);
    buf[CERT_SIZE - 1] = blk->cert.id;

    uint256_serialize_be(&blk->prevHash, buf + CERT_SIZE, UINT256_SIZE);
    serialize_u64_be(blk->height, buf + CERT_SIZE + UINT256_SIZE);
    serialize_u64_be(blk->timestamp, buf + CERT_SIZE + UINT256_SIZE + UINT64_SIZE);
    serialize_u8(blk->tier, buf + CERT_SIZE + UINT256_SIZE + 2 * UINT64_SIZE);

    hash256_buffer(buf, packed_len, &pow->challenge);

    pow->complexity = complexity;

    return OP_SUCCESS;
}

#endif // TIER_POW_CHALLENGE_H
