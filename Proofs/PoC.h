#ifndef POC_H
#define POC_H

#include <stdint.h>
#include "datatype/uint256_t.h"
#include "util/utilities.h"

#if !defined(__linux__)
#error "This implementation is Linux optimized only"
#endif

#define MINI_POW_INLINE static inline __attribute__((always_inline))

/*
 * mini_pow_t:
 *  - 32-byte aligned
 *  - deterministic 256-bit challenge
 *  - complexity 0-255 bits
 *  - optional padding for cache alignment
 */
typedef struct __attribute__((aligned(32))) {
    uint256 challenge;   // 32 bytes
    uint8_t complexity;  // 1 byte
    uint8_t reserved[7]; // padding to make 32-byte multiple
} mini_pow_t;


MINI_POW_INLINE void mini_pow_init(mini_pow_t * pow){
    uint256_zero(&pow->challenge);
    pow->complexity = 0;
    memset(pow->reserved, 0, sizeof(pow->reserved));
}

MINI_POW_INLINE const uint256* mini_pow_get_challenge_ptr(const mini_pow_t * pow){
    return &pow->challenge;
}

MINI_POW_INLINE uint8_t mini_pow_get_complexity(const mini_pow_t * pow){
    return pow->complexity;
}

MINI_POW_INLINE void mini_pow_set_challenge(mini_pow_t * pow, const uint256 * challenge){
    uint256_copy(&pow->challenge, challenge);
}

MINI_POW_INLINE void mini_pow_set_complexity(mini_pow_t * pow, uint8_t complexity){
    pow->complexity = complexity;
}

MINI_POW_INLINE void mini_pow_copy(mini_pow_t * dst, const mini_pow_t * src){
    uint256_copy(&dst->challenge, &src->challenge);
    dst->complexity = src->complexity;
    memset(dst->reserved, 0, sizeof(dst->reserved));
}

/*
 * generate_Challenge:
 *  - Computes SHA256 hash over the block struct
 *  - Uses HASH256_OF from utilities.h (zero-copy)
 *  - Returns mini_pow_t with challenge and specified complexity
 */
MINI_POW_INLINE mini_pow_t generate_Challenge(const void* block, size_t block_size, uint8_t complexity)
{
    mini_pow_t pow;

    // Zero-copy deterministic hash
    hash256_buffer(block, block_size, &pow.challenge);

    // Set PoW complexity
    pow.complexity = complexity;

    return pow;
}

#endif // POC_H
