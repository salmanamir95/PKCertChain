#ifndef MINI_POW_SOLVE_H
#define MINI_POW_SOLVE_H

#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include "miniPoWChallenge.h"
#include "datatype/uint256_t.h"
#include "datatype/uint512.h"
#include "datatype/OpStatus.h"
#include "util/utilities.h"
#if !defined(__linux__)
#error "This implementation is Linux optimized only"
#endif

#define MINI_POW_SOLVE_INLINE static inline __attribute__((always_inline))

typedef struct __attribute__((aligned(32)))
{
    uint64_t nonce;     // 8 bytes
    uint8_t complexity; // 1 byte
    uint8_t challenge_id; //1 byte
    uint8_t reserved[22];
} mini_pow_solve_t;

MINI_POW_SOLVE_INLINE void mini_pow_solve_init(mini_pow_solve_t *pow)
{
    pow->nonce = 0;
    pow->complexity = 0;
    pow->challenge_id = 0;
    memset(pow->reserved, 0, sizeof(pow->reserved));
}

MINI_POW_SOLVE_INLINE uint64_t *mini_pow_solve_get_nonce(mini_pow_solve_t *pow)
{
    return &pow->nonce;
}

MINI_POW_SOLVE_INLINE uint8_t mini_pow_solve_get_complexity(mini_pow_solve_t *pow)
{
    return pow->complexity;
}

MINI_POW_SOLVE_INLINE uint8_t mini_pow_solve_get_challenge_id(mini_pow_solve_t *pow)
{
    return pow->challenge_id;
}

MINI_POW_SOLVE_INLINE void mini_pow_solve_set_nonce(mini_pow_solve_t *pow, uint64_t nonce)
{
    pow->nonce = nonce;
}

MINI_POW_SOLVE_INLINE void mini_pow_solve_set_challenge_id(mini_pow_solve_t*pow, uint8_t challenge_id){
    pow->challenge_id = challenge_id;
}

MINI_POW_SOLVE_INLINE void mini_pow_solve_set_complexity(mini_pow_solve_t * pow, uint8_t complexity){
    pow->complexity = complexity;
}

MINI_POW_SOLVE_INLINE OpStatus_t mini_pow_solve_serialize(mini_pow_solve_t *pow, uint8_t *buf, size_t len)
{
    if (!pow || !buf)
        return OP_NULL_PTR;
    if (len < MINI_POW_SOLVE_SIZE)
        return OP_BUF_TOO_SMALL;

    OpStatus_t status = uint64_t_serialize(pow->nonce, buf, UINT64_SIZE);
    if (status != OP_SUCCESS) return status;
    buf[8] = pow->complexity;
    buf[9] = pow->challenge_id;
    return OP_SUCCESS;
}

MINI_POW_SOLVE_INLINE OpStatus_t mini_pow_solve_deserialize(mini_pow_solve_t *pow, uint8_t *buf, size_t len)
{
    if (!pow || !buf)
        return OP_NULL_PTR;
    if (len < MINI_POW_SOLVE_SIZE)
        return OP_BUF_TOO_SMALL;

    memcpy(&pow->nonce, buf, 8);
    pow->nonce = be64toh(pow->nonce);
    pow->complexity = buf[8];
    pow->challenge_id = buf[9];
    return OP_SUCCESS;
}
//exactly check the first n bits exactly zero and no more should be zero
MINI_POW_SOLVE_INLINE bool check_complexity_met(uint256 *hash, uint8_t complexity)
{
    if (complexity > 255) return false;  // maximum valid complexity

    uint16_t leading_zeros = clz256(hash);

    // Map to your “complexity counts from 0 = first bit must be 1”
    return leading_zeros == (uint16_t)(complexity + 1);
}



MINI_POW_SOLVE_INLINE void mini_pow_solve_solve_challenge(mini_pow_challenge_t *pow, mini_pow_solve_t **solved)
{
    bool found = false;
    uint8_t comp = mini_pow_challenge_get_complexity(pow);
    const uint256 *challenge = mini_pow_challenge_get_challenge(pow);
    uint256 hash;
    uint64_t i_serialize;
    uint8_t buf[UINT64_SIZE];
    uint8_t buf512[UINT512_SIZE];
    uint512 concat;
    OpStatus_t status;
    for (uint64_t i = 0; i <= UINT64_MAX && !found; i++)
    {
        status = uint64_t_serialize(i, buf, UINT64_SIZE);
        if (status != OP_SUCCESS)
            continue;
        hash256_buffer(buf, UINT64_SIZE, &hash);
        uint512_from_two_uint256(&concat, &pow->challenge, &hash);
        status = uint512_serialize(&concat, buf512, UINT512_SIZE);
        if (status != OP_SUCCESS) continue;
        hash256_buffer(buf512, UINT512_SIZE, &hash);
        if (check_complexity_met(&hash, pow->complexity))
            found = true;
    }

    if(!found)
        *solved = NULL;
    else
    {
        mini_pow_solve_set_challenge_id(*solved, pow->challenge_id);
        mini_pow_solve_set_complexity(*solved, pow->complexity);
        uint64_t nonce;
        status = uint64_t_deserialize(&nonce, buf, UINT64_SIZE);
        mini_pow_solve_set_nonce(*solved, nonce);
    }

}
#endif // MINI_POW_SOLVE_H