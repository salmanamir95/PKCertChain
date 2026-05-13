#ifndef MINI_POW_RESULT_H
#define MINI_POW_RESULT_H

#include <stdint.h>
#include <stdbool.h>
#include "Proofs/MiniPoW/solvedMatricPoW.h"
#include "Proofs/MiniPoW/miniPoWMatrix.h"
#include "core/enums/Tier.h"

// The final result returned by the manager
typedef struct {
    uint32_t challengeid;
    uint32_t sessionid;
    const mini_pow_Matrix *minipowmatrix;
    const SolvedMatricPoW *solvedmatrix;
    Tier_t tier;
    bool isValid;
} mini_pow_result;

#define MINI_POW_RESULT_SERIALIZED_SIZE 12

typedef struct __attribute__((aligned(4))) {
    uint32_t challengeid; // 4
    uint32_t sessionid;   // 4
    Tier_t tier;          // 1
    bool isValid;         // 1
    uint8_t reserved[2];  // 2 -> Total 12
} MiniPowResult;

static inline __attribute__((always_inline)) void minipowresult_init(MiniPowResult *res) {
    res->challengeid = 0;
    res->sessionid = 0;
    res->tier = TIER_INVALID;
    res->isValid = false;
    res->reserved[0] = 0; res->reserved[1] = 0;
}

/* Moved to NetworkSerialization.h */


/* Moved to NetworkSerialization.h */


#endif // MINI_POW_RESULT_H
