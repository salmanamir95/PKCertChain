#ifndef MINI_POW_VERIFY_H
#define MINI_POW_VERIFY_H


#include "core/Global_Size_Offsets.h"

#include <stdint.h>
#include <stdbool.h>
#include "shared/protocol/proofs/mini_pow/mini_pow_Matrix.h"
#include "shared/protocol/proofs/mini_pow/SolvedMatricPoW.h"
#include "shared/core/enums/OpStatus.h"

#ifndef MINI_POW_VERIFY_INLINE
#define MINI_POW_VERIFY_INLINE static inline __attribute__((always_inline))
#endif

/*
 * Verifies the submitted solution against the generated matrices A and B.
 * It computes A x B via the standard dot-product method and ensures every cell matches 
 * the progressively accumulated Outer-Product result matrix in solve.
 */
MINI_POW_VERIFY_INLINE bool mini_pow_verify(const SolvedMatricPoW *solvedmatrix, const mini_pow_Matrix *matrices)
{
    if (!solvedmatrix || !matrices) return false;

    for (size_t row = 0; row < MINI_POW_MATRIX_N; ++row) {
        for (size_t col = 0; col < MINI_POW_MATRIX_N; ++col) {
            
            uint32_t expected_val = 0;
            // Compute inner dot product for element (row, col)
            for (size_t k = 0; k < MINI_POW_MATRIX_N; ++k) {
                expected_val += (uint32_t)matrices->A[row][k] * (uint32_t)matrices->B[k][col];
            }
            
            // Check if it exactly matches the submitted solved matrix
            if (solvedmatrix->Matrix[row][col] != expected_val) {
                return false;
            }
        }
    }

    return true;
}

#endif // MINI_POW_VERIFY_H
