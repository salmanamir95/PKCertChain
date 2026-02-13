#ifndef MINI_POW_CHALLENGE_H
#define MINI_POW_CHALLENGE_H

#include <stdint.h>
#include "datatype/OpStatus.h"
#include "blockchain/block.h"
#include "datatype/uint256_t.h"
#include "util/utilities.h"

#if !defined(__linux__)
#error "This implementation is Linux optimized only"
#endif

#define MINI_POW_CHALLENGE_INLINE static inline __attribute__((always_inline))

/*
 * mini_pow_challenge_t:
 *  - 32-byte aligned
 *  - deterministic 256-bit challenge
 *  - complexity 0-255 bits
 *  - optional padding for cache alignment
 */
typedef struct __attribute__((aligned(32))) {
    uint256 challenge;   // 32 bytes
    uint8_t complexity;  // 1 byte
    uint8_t challenge_id; // 1 byte
    uint8_t reserved[30]; // padding to make 32-byte multiple
} mini_pow_challenge_t;


MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_init(mini_pow_challenge_t * pow){
    uint256_zero(&pow->challenge);
    pow->complexity = 0;
    memset(pow->reserved, 0, sizeof(pow->reserved));
}

MINI_POW_CHALLENGE_INLINE const uint256* mini_pow_challenge_get_challenge(const mini_pow_challenge_t * pow){
    return &pow->challenge;
}

MINI_POW_CHALLENGE_INLINE const uint8_t* mini_pow_challenge_get_challenge_id(const mini_pow_challenge_t * pow){
    return &pow->challenge_id;
}

MINI_POW_CHALLENGE_INLINE const uint8_t mini_pow_challenge_get_complexity(const mini_pow_challenge_t * pow){
    return pow->complexity;
}

MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_set_challenge(mini_pow_challenge_t * pow, const uint256 * challenge){
    uint256_copy(&pow->challenge, challenge);
}

MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_set_complexity(mini_pow_challenge_t * pow, uint8_t complexity){
    pow->complexity = complexity;
}

MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_set_challenge_id(mini_pow_challenge_t * pow, uint8_t id){
    pow->challenge_id = id;
}

MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_copy(mini_pow_challenge_t * dst, const mini_pow_challenge_t * src){
    uint256_copy(&dst->challenge, &src->challenge);
    dst->complexity = src->complexity;
    memset(dst->reserved, 0, sizeof(dst->reserved));
}

/*
 * generate_Challenge:
 *  - Computes SHA256 hash over the block struct
 *  - Uses HASH256_OF from utilities.h (zero-copy)
 *  - Returns mini_pow_challenge_t with challenge and specified complexity
 */
MINI_POW_CHALLENGE_INLINE OpStatus_t generate_mini_pow_Challenge(block* block, uint8_t complexity, mini_pow_challenge_t* pow)
{
    uint8_t* buf = new uint8_t [BLOCK_SIZE];

    OpStatus_t status = block_serialize(block, buf, BLOCK_SIZE);
    if (status != OP_SUCCESS) return status;


    hash256_buffer(buf, BLOCK_SIZE, &pow->challenge);

    // Zero-copy deterministic hash
    hash256_buffer(buf, BLOCK_SIZE, &pow->challenge);

    // Set PoW complexity
    pow->complexity = complexity;

    return OP_SUCCESS;
}

#define MINI_POW_CHALLENGE_SIZE 34

MINI_POW_CHALLENGE_H OpStatus_t mini_pow_challenge_serialize(mini_pow_challenge_t *pow, uint8_t* buf, size_t buf_len)
{
    if (!pow || !buf) return OP_NULL_PTR;
    if (buf_len < MINI_POW_CHALLENGE_SIZE) return OP_BUF_TOO_SMALL;

    OpStatus_t status = uint256_serialize(&pow->challenge, buf, sizeof(buf));
    if (status != OP_SUCCESS) return status;

    buf[32] = pow->complexity;
    buf[33] = pow->challenge_id;

    return OP_SUCCESS;  
}


MINI_POW_CHALLENGE_H OpStatus_t mini_pow_challenge_deserialize(mini_pow_challenge_t *pow, uint8_t* buf, size_t buf_len)
{
    if (!pow || !buf) return OP_NULL_PTR;
    if (buf_len < MINI_POW_CHALLENGE_SIZE) return OP_BUF_TOO_SMALL;

    OpStatus_t status = uint256_deserialize(&pow->challenge, buf, sizeof(buf));
    if (status != OP_SUCCESS) return status;
    pow->complexity = buf[32];
    pow->challenge_id = buf[33];

    return OP_SUCCESS;  
}



#endif // MINI_POW_CHALLENGE_H
