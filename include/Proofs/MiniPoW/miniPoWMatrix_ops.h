#ifndef MINI_POW_MATRIX_H
#define MINI_POW_MATRIX_H


#include "shared/core/Global_Size_Offsets.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "shared/core/datatypes/uint256_t.h"
#include "shared/core/enums/OpStatus.h"
#include "shared/blockchain/certificate.h"
#include "shared/crypto/SeedUtil.h"
#include "shared/protocol/proofs/mini_pow/mini_pow_Classify_t.h"

#ifndef MINI_POW_MATRIX_INLINE
#define MINI_POW_MATRIX_INLINE static inline __attribute__((always_inline))
#endif

/*
 * MiniPoW Challenge Matrices
 * Contains the deterministic seed assigned to the miner,
 * and the two 1000x1000 matrices A and B populated securely via CSPRNG.
 */
// typedef struct __attribute__((aligned(4))) {
//     uint256 seed;
//     uint16_t A[MINI_POW_MATRIX_N][MINI_POW_MATRIX_N];
//     uint16_t B[MINI_POW_MATRIX_N][MINI_POW_MATRIX_N];
// } mini_pow_Matrix;

/*
 * Construct the MiniPoW matrices (Seed + A + B)
 * Takes in the miner's certificate, last block hash, session ID, and specific challenge ID.
 * Generates the deterministic 256-bit seed, then samples HMAC_DRBG securely (2M times) to build matrices.
 */
MINI_POW_MATRIX_INLINE OpStatus_t construct_mini_pow_matrices(const certificate *miner_cert,
                                                              const uint256 *lastBlockHash,
                                                              const uint32_t sessionId,
                                                              const uint32_t challengeID,
                                                              mini_pow_Matrix *out_matrices)
{
    if (!miner_cert || !lastBlockHash || !out_matrices) return OP_INVALID_INPUT;

    // 1. Generate the deterministically unique seed
    OpStatus_t st = mini_pow_seed_gen(miner_cert, lastBlockHash, &sessionId, &challengeID, &out_matrices->seed);
    if (st != OP_SUCCESS) return st;

    // 2. Populate Matrix A: Iterations 0 to 999,999
    uint32_t iteration = 0;
    for (uint32_t i = 0; i < MINI_POW_MATRIX_N; ++i) {
        for (uint32_t j = 0; j < MINI_POW_MATRIX_N; ++j) {
            st = mini_pow_csprng(&out_matrices->seed, &iteration, &out_matrices->A[i][j]);
            if (st != OP_SUCCESS) return st;
            iteration++;
        }
    }

    // 3. Populate Matrix B: Iterations 1,000,000 to 1,999,999
    for (uint32_t i = 0; i < MINI_POW_MATRIX_N; ++i) {
        for (uint32_t j = 0; j < MINI_POW_MATRIX_N; ++j) {
            st = mini_pow_csprng(&out_matrices->seed, &iteration, &out_matrices->B[i][j]);
            if (st != OP_SUCCESS) return st;
            iteration++;
        }
    }

    return OP_SUCCESS;
}

#endif // MINI_POW_MATRIX_H
