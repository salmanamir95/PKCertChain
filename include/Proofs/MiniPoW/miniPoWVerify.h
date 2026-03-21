#ifndef MINI_POW_SOLVE_VERIFY_H
#define MINI_POW_SOLVE_VERIFY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#define MINI_POW_VERIFY_INLINE static inline __attribute__((always_inline))
#include "Proofs/MiniPoW/miniPoWChallenge.h"
#include "Proofs/MiniPoW/miniPoWSolve.h"


MINI_POW_VERIFY_INLINE bool isValidChallenge(const mini_pow_challenge_t* pow, const mini_pow_solve_t* solve){
    if(!solve || !pow) return false;
    if (!(solve->challenge_id == pow->challenge_id)) return false;

    uint256 hash;
    OpStatus_t status;
    uint8_t buf[UINT64_SIZE];
    uint8_t buf512[UINT512_SIZE];
    uint512 concat;

    status = uint64_t_serialize(solve->nonce, buf, UINT64_SIZE);
    if (status != OP_SUCCESS) return false;
    hash256_buffer(buf, UINT64_SIZE, &hash);
    uint512_from_two_uint256(&concat, &pow->challenge, &hash);
    status = uint512_serialize(&concat, buf512, UINT512_SIZE);
    if (status != OP_SUCCESS) return false;
    hash256_buffer(buf512,UINT512_SIZE,&hash);
    return check_complexity_met(&hash, pow->complexity);
}

#endif // MINI_POW_SOLVE_VERIFY_H