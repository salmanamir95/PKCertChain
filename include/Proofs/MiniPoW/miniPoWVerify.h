#ifndef MINI_POW_SOLVE_VERIFY_H
#define MINI_POW_SOLVE_VERIFY_H

#include "pkcertchain_config.h"



#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#define MINI_POW_VERIFY_INLINE static inline __attribute__((always_inline))
#include "Proofs/MiniPoW/miniPoWChallenge.h"
#include "Proofs/MiniPoW/miniPoWSolve.h"
#include "util/To_BO_Def_Primitives.h"
#include "datatype/OpStatus.h"


MINI_POW_VERIFY_INLINE bool isValidChallenge(const mini_pow_challenge_t* pow, const mini_pow_solve_t* solve){
    if(!solve || !pow) return false;
    if (!(solve->challenge_id == pow->challenge_id)) return false;

    uint256 hash;
    uint8_t nonce_buf[UINT64_SIZE];
    uint8_t concat_buf[UINT256_SIZE * 2];

    serialize_u64_be(solve->nonce, nonce_buf);
    hash256_buffer(nonce_buf, UINT64_SIZE, &hash);
    uint256_serialize_two_be(&pow->challenge, &hash, concat_buf, UINT256_SIZE * 2);
    hash256_buffer(concat_buf, sizeof(concat_buf), &hash);
    return check_complexity_met(&hash, pow->complexity);
}

MINI_POW_VERIFY_INLINE OpStatus_t mini_pow_verify_serialize_inputs(const mini_pow_challenge_t *pow,
                                                                   const mini_pow_solve_t *solve,
                                                                   uint8_t *out,
                                                                   size_t out_size)
{
    if (!pow || !solve || !out) return OP_NULL_PTR;
    if (out_size < (MINI_POW_CHALLENGE_SIZE + MINI_POW_SOLVE_SIZE)) return OP_BUF_TOO_SMALL;

    if (mini_pow_challenge_serialize(pow, out, MINI_POW_CHALLENGE_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (mini_pow_solve_serialize(solve, out + MINI_POW_CHALLENGE_SIZE, MINI_POW_SOLVE_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    return OP_SUCCESS;
}

MINI_POW_VERIFY_INLINE OpStatus_t mini_pow_verify_deserialize_inputs(const uint8_t *in,
                                                                     size_t in_size,
                                                                     mini_pow_challenge_t *pow,
                                                                     mini_pow_solve_t *solve)
{
    if (!pow || !solve || !in) return OP_NULL_PTR;
    if (in_size < (MINI_POW_CHALLENGE_SIZE + MINI_POW_SOLVE_SIZE)) return OP_BUF_TOO_SMALL;

    if (mini_pow_challenge_deserialize(in, MINI_POW_CHALLENGE_SIZE, pow) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (mini_pow_solve_deserialize(in + MINI_POW_CHALLENGE_SIZE, MINI_POW_SOLVE_SIZE, solve) != OP_SUCCESS) return OP_INVALID_INPUT;
    return OP_SUCCESS;
}

#endif // MINI_POW_SOLVE_VERIFY_H
