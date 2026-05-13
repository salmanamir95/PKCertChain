#ifndef TIER_POW_RESULT_H
#define TIER_POW_RESULT_H

#include "pkcertchain_config.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "enums/Tier.h"
#include "Proofs/TierPoW/tierPoWChallenge.h"
#include "Proofs/TierPoW/tierPoWSolve.h"
#include "util/NetworkSerialization.h"
#include "util/NetworkSerialization.h"
#include "enums/OpStatus.h"

// Total serialized size: 1 + 3 + 44 + 20 + 8 = 76 bytes
typedef struct __attribute__((aligned(4))) {
    Tier_t tier;                      
    uint8_t reserved[3];              
    tier_pow_challenge_t challenge;   
    tier_pow_solve_t solve;           
    double time_taken;                
} TierPowResult;

#define TIER_POW_RESULT_SERIALIZED_SIZE (1 + 3 + 44 + 20 + 8) 

static inline void tierpowresult_init(TierPowResult *res) {
    if (!res) return;
    res->tier = TIER_INVALID;
    memset(res->reserved, 0, 3);
    memset(&res->challenge, 0, sizeof(res->challenge));
    tier_pow_solve_init(&res->solve);
    res->time_taken = 0.0;
}

/* Moved to NetworkSerialization.h */


/* Moved to NetworkSerialization.h */


#endif // TIER_POW_RESULT_H
