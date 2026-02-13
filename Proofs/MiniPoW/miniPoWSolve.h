#ifndef MINI_POW_SOLVE_H
#define MINI_POW_SOLVE_H

#include <endian.h>
#include "miniPoWChallenge.h"
#include "datatype/uint256_t.h"
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
    uint8_t reserved[23];
} mini_pow_solve_t;

MINI_POW_SOLVE_H void mini_pow_solve_init(mini_pow_solve_t *pow)
{
    pow->nonce = 0;
    pow->complexity = 0;
    memset(pow->reserved, 0, sizeof(pow->reserved));
}

MINI_POW_SOLVE_H uint64_t *mini_pow_solve_get_nonce(mini_pow_solve_t *pow)
{
    return &pow->nonce;
}

MINI_POW_SOLVE_H uint8_t mini_pow_solve_get_complexity(mini_pow_solve_t *pow)
{
    return pow->complexity;
}

MINI_POW_SOLVE_H void mini_pow_solve_set_nonce(mini_pow_solve_t *pow, uint8_t nonce)
{
    pow->nonce = nonce;
}

MINI_POW_SOLVE_H void mini_pow_solve_complexity(mini_pow_solve_t *pow, uint8_t comp)
{
    pow->complexity = comp;
}

#define Solve_Block_Size 9

MINI_POW_SOLVE_H OpStatus_t mini_pow_solve_serialize(mini_pow_solve_t *pow, uint8_t *buf, size_t len)
{
    if (!pow || !buf)
        return OP_NULL_PTR;
    if (sizeof(buf) < Solve_Block_Size || len < Solve_Block_Size)
        return OP_BUF_TOO_SMALL;

    memset(buf, htobe64(pow->complexity), sizeof(pow->complexity));
    buf[8] = pow->complexity;
    return OP_SUCCESS;
}

MINI_POW_SOLVE_H OpStatus_t mini_pow_solve_deserialize(mini_pow_solve_t *pow, uint8_t *buf, size_t len)
{
    if (!pow || !buf)
        return OP_NULL_PTR;
    if (sizeof(buf) < Solve_Block_Size || len < Solve_Block_Size)
        return OP_BUF_TOO_SMALL;

    memcpy(&pow->nonce, buf, 8);
    pow->nonce = be64toh(pow->nonce);
    pow->complexity = buf[8];
    return OP_SUCCESS;
}

MINI_POW_SOLVE_H void mini_pow_solve_solve_challenge(mini_pow_challenge_t *pow)
{
    bool found = false;
    uint8_t comp = mini_pow_challenge_get_complexity(pow);
    const uint256* challenge = mini_pow_challenge_get_challenge(pow);
    uint256* hash= nullptr;
    uint64_t i_serialize;
    uint8_t* buf = new uint8_t[UINT64_SIZE];
    for(uint64_t i=0; i<=UINT64_MAX && !found; i++)
    {
        i_serialize = uint64_t_serialize(i,buf,UINT64_SIZE);
        hash256_buffer(buf, UINT64_SIZE, hash);
    }
}
#endif // MINI_POW_SOLVE_H