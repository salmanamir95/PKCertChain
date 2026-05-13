#ifndef TIER_POW_SOLVE_VERIFY_H
#define TIER_POW_SOLVE_VERIFY_H



#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#define TIER_POW_VERIFY_INLINE static inline __attribute__((always_inline))

#include "shared/proofs/tier_pow/tierPoWChallenge.h"
#include "shared/proofs/tier_pow/tierPoWSolve.h"
#include "shared/net/NetworkSerialization.h"
#include "shared/core/enums/OpStatus.h"

TIER_POW_VERIFY_INLINE bool isValidTierChallenge(const tier_pow_challenge_t* pow,
                                                 const tier_pow_solve_t* solve)
{
    if(!solve || !pow) return false;
    if (!(solve->challenge_id == pow->challenge_id)) return false;

    uint256 hash;
    uint8_t nonce_buf[UINT64_SIZE];
    uint8_t concat_buf[UINT256_SIZE * 2];

    serialize_u64_be(solve->nonce, nonce_buf);
    hash256_buffer(nonce_buf, UINT64_SIZE, &hash);
    uint256_serialize_two_be(&pow->challenge, &hash, concat_buf, UINT256_SIZE * 2);
    hash256_buffer(concat_buf, sizeof(concat_buf), &hash);
    return tier_pow_check_complexity_met(&hash, pow->complexity);
}

/* Moved to NetworkSerialization.h */


/* Moved to NetworkSerialization.h */


#endif // TIER_POW_SOLVE_VERIFY_H
