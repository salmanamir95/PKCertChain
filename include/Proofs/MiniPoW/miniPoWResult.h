#ifndef MINI_POW_RESULT_H
#define MINI_POW_RESULT_H

#include <stdint.h>
#include <stdbool.h>
#include "Proofs/MiniPoW/solvedMatricPoW.h"
#include "Proofs/MiniPoW/miniPoWMatrix.h"
#include "blockchain/Tier.h"

// The final result returned by the manager
typedef struct {
    uint32_t challengeid;
    uint32_t sessionid;
    const mini_pow_Matrix *minipowmatrix;
    const SolvedMatricPoW *solvedmatrix;
    Tier_t tier;
    bool isValid;
} mini_pow_result;

#endif // MINI_POW_RESULT_H
