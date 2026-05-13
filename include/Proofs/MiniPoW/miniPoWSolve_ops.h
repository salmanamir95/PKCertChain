#ifndef MINI_POW_SOLVE_H
#define MINI_POW_SOLVE_H


#include "core/Global_Size_Offsets.h"

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "shared/protocol/proofs/mini_pow/mini_pow_challenge_t.h"
#include "shared/protocol/proofs/mini_pow/mini_pow_Classify_t.h"
#include "shared/core/enums/OpStatus.h"

#ifndef MINI_POW_SOLVE_INLINE
#define MINI_POW_SOLVE_INLINE static inline __attribute__((always_inline))
#endif

/*
 * MiniPoW Solve structure
 * Holds the resulting matrix C (1000 x 1000) where C = A * B.
 * Each entry is a uint32_t to avoid overflow from multiplying two uint16_t's.
//  */
// typedef struct __attribute__((aligned(4))) {
//     uint32_t resultMatrix[MINI_POW_MATRIX_N][MINI_POW_MATRIX_N];
// } mini_pow_solve_t;

/*
 * Initializes the solve state with a zero matrix.
 */
MINI_POW_SOLVE_INLINE void mini_pow_solve_init(mini_pow_solve_t *solve)
{
    if (!solve) return;
    memset(solve->resultMatrix, 0, sizeof(solve->resultMatrix));
}

/*
 * Updates the state using the outer product of the i-th column of A and the i-th row of B.
 * Adds the result into the state C.
 */
MINI_POW_SOLVE_INLINE OpStatus_t mini_pow_solve_update(mini_pow_solve_t *solve, 
                                                       const mini_pow_challenge_t *challenge)
{
    if (!solve || !challenge) return OP_NULL_PTR;

    uint32_t iteration = challenge->iteration;
    
    // Bounds check: maximum iterations = 1000
    if (iteration >= MINI_POW_MATRIX_N) {
        return OP_INVALID_INPUT;
    }

    // Outer product of columnOfA (size N) and rowOfB (size N) -> Matrix size NxN
    for (size_t row = 0; row < MINI_POW_MATRIX_N; ++row) {
        uint32_t a_val = challenge->columnOfA[row];
        for (size_t col = 0; col < MINI_POW_MATRIX_N; ++col) {
            solve->resultMatrix[row][col] += a_val * (uint32_t)challenge->rowOfB[col];
        }
    }

    return OP_SUCCESS;
}

#endif // MINI_POW_SOLVE_H
