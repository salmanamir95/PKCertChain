#ifndef TIER_POW_SOLVE_H
#define TIER_POW_SOLVE_H

#include "pkcertchain_config.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "Proofs/TierPoW/tierPoWChallenge.h"
#include "datatype/uint256_t.h"
#include "util/SignUtils.h"
#include "util/To_BO_Def_Primitives.h"
#include "util/Size_Offsets.h"
#include "datatype/OpStatus.h"

#define TIER_POW_SOLVE_INLINE static inline __attribute__((always_inline))

#define TIER_POW_SOLVE_SERIALIZED_SIZE TIER_POW_SOLVE_SIZE

typedef struct __attribute__((aligned(4)))
{
    uint64_t nonce;     // 8 bytes
    uint8_t complexity; // 1 byte
    uint64_t challenge_id; // 8 bytes
    uint8_t reserved[3];
} tier_pow_solve_t;

TIER_POW_SOLVE_INLINE void tier_pow_solve_init(tier_pow_solve_t *pow)
{
    pow->nonce = 0;
    pow->complexity = 0;
    pow->challenge_id = 0;
    memset(pow->reserved, 0, sizeof(pow->reserved));
}

TIER_POW_SOLVE_INLINE uint64_t *tier_pow_solve_get_nonce(tier_pow_solve_t *pow)
{
    return &pow->nonce;
}

TIER_POW_SOLVE_INLINE uint8_t tier_pow_solve_get_complexity(tier_pow_solve_t *pow)
{
    return pow->complexity;
}

TIER_POW_SOLVE_INLINE uint64_t tier_pow_solve_get_challenge_id(tier_pow_solve_t *pow)
{
    return pow->challenge_id;
}

TIER_POW_SOLVE_INLINE void tier_pow_solve_set_nonce(tier_pow_solve_t *pow, uint64_t nonce)
{
    pow->nonce = nonce;
}

TIER_POW_SOLVE_INLINE void tier_pow_solve_set_challenge_id(tier_pow_solve_t *pow, uint64_t challenge_id)
{
    pow->challenge_id = challenge_id;
}

TIER_POW_SOLVE_INLINE void tier_pow_solve_set_complexity(tier_pow_solve_t *pow, uint8_t complexity)
{
    pow->complexity = complexity;
}

TIER_POW_SOLVE_INLINE OpStatus_t tier_pow_solve_serialize(const tier_pow_solve_t *pow,
                                                          uint8_t *out,
                                                          size_t out_size)
{
    if (!pow || !out) return OP_NULL_PTR;
    if (out_size < TIER_POW_SOLVE_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    serialize_u64_be(pow->nonce, out);
    serialize_u8(pow->complexity, out + UINT64_SIZE);
    serialize_u64_be(pow->challenge_id, out + UINT64_SIZE + 1);
    memcpy(out + UINT64_SIZE + 1 + UINT64_SIZE, pow->reserved, sizeof(pow->reserved));
    return OP_SUCCESS;
}

TIER_POW_SOLVE_INLINE OpStatus_t tier_pow_solve_deserialize(const uint8_t *in,
                                                            size_t in_size,
                                                            tier_pow_solve_t *pow)
{
    if (!pow || !in) return OP_NULL_PTR;
    if (in_size < TIER_POW_SOLVE_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    deserialize_u64_be(in, &pow->nonce, sizeof(uint64_t));
    pow->complexity = in[UINT64_SIZE];
    deserialize_u64_be(in + UINT64_SIZE + 1, &pow->challenge_id, sizeof(uint64_t));
    memcpy(pow->reserved, in + UINT64_SIZE + 1 + UINT64_SIZE, sizeof(pow->reserved));
    return OP_SUCCESS;
}

// exactly check the first n bits exactly zero and no more should be zero
TIER_POW_SOLVE_INLINE bool tier_pow_check_complexity_met(uint256 *hash, uint8_t complexity)
{
    if (complexity > 255) return false;

    uint16_t leading_zeros = clz256(hash);
    return leading_zeros == (uint16_t)(complexity + 1);
}

TIER_POW_SOLVE_INLINE void tier_pow_solve_challenge(tier_pow_challenge_t *pow, tier_pow_solve_t **solved)
{
    bool found = false;
    uint64_t found_nonce = 0;
    const uint256 *challenge = tier_pow_challenge_get_challenge(pow);
    uint256 hash;
    uint8_t nonce_buf[UINT64_SIZE];
    uint8_t concat_buf[UINT256_SIZE * 2];
    for (uint64_t i = 0; i <= UINT64_MAX && !found; i++)
    {
        serialize_u64_be(i, nonce_buf);
        hash256_buffer(nonce_buf, UINT64_SIZE, &hash);
        uint256_serialize_two_be(challenge, &hash, concat_buf, UINT256_SIZE * 2);
        hash256_buffer(concat_buf, sizeof(concat_buf), &hash);
        if (tier_pow_check_complexity_met(&hash, pow->complexity)) {
            found = true;
            found_nonce = i;
        }
    }

    if(!found)
        *solved = NULL;
    else
    {
        tier_pow_solve_set_challenge_id(*solved, pow->challenge_id);
        tier_pow_solve_set_complexity(*solved, pow->complexity);
        tier_pow_solve_set_nonce(*solved, found_nonce);
    }

}

#endif // TIER_POW_SOLVE_H
