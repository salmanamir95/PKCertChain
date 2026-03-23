#ifndef MINI_POW_SOLVE_VERIFY_H
#define MINI_POW_SOLVE_VERIFY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#define MINI_POW_VERIFY_INLINE static inline __attribute__((always_inline))
#include "Proofs/MiniPoW/miniPoWChallenge.h"
#include "Proofs/MiniPoW/miniPoWSolve.h"
#include "util/To_BO_Def_Primitives.h"


MINI_POW_VERIFY_INLINE bool isValidChallenge(const mini_pow_challenge_t* pow, const mini_pow_solve_t* solve){
    if(!solve || !pow) return false;
    if (!(solve->challenge_id == pow->challenge_id)) return false;

    uint256 hash;
    uint8_t nonce_buf[UINT64_SIZE];
    uint8_t concat_buf[UINT256_SIZE * 2];

    serialize_u64_be(solve->nonce, nonce_buf);
    hash256_buffer(nonce_buf, UINT64_SIZE, &hash);
    serialize_two_uint256_be(&pow->challenge, &hash, concat_buf);
    hash256_buffer(concat_buf, sizeof(concat_buf), &hash);
    return check_complexity_met(&hash, pow->complexity);
}

#endif // MINI_POW_SOLVE_VERIFY_H
