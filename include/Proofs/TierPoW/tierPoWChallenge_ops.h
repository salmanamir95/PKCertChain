#ifndef TIER_POW_CHALLENGE_H
#define TIER_POW_CHALLENGE_H



#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "core/enums/OpStatus.h"
#include "core/datatypes/uint256_t.h"
#include "core/datatypes/uint256_t.h"
#include "crypto/SignUtils.h"
#include "net/NetworkSerialization.h"
#include "core/Global_Size_Offsets.h"

#define TIER_POW_CHALLENGE_INLINE static inline __attribute__((always_inline))

#define TIER_POW_CHALLENGE_SERIALIZED_SIZE TIER_POW_CHALLENGE_SIZE

/*
 * tier_pow_challenge_t:
 *  - 4-byte aligned (32-bit alignment)
 *  - deterministic 256-bit challenge
 *  - complexity 0-255 bits
 *  - padding to keep size a 32-bit multiple
 */
// typedef struct __attribute__((aligned(4))) {
//     uint256 challenge;   // 32 bytes
//     uint8_t complexity;  // 1 byte
//     uint64_t challenge_id; // 8 bytes
//     uint8_t reserved[3]; // padding to make 32-bit multiple
// } tier_pow_challenge_t;

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

/* Moved to NetworkSerialization.h */


/* Moved to NetworkSerialization.h */


#endif // TIER_POW_CHALLENGE_H
