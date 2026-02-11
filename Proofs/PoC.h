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
