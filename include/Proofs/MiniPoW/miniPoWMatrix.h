#ifndef MINI_POW_MATRIX_H
#define MINI_POW_MATRIX_H

#include "pkcertchain_config.h"

#include <stdint.h>
#include <stddef.h>
#include "Proofs/MiniPoW/miniPoWClassify.h"
#include "datatype/OpStatus.h"

/*
 * Validator-side matrix container.
 * A and B are generated deterministically from chain state (seeded CSPRNG).
 * Miner only receives row/col/iteration identifiers, not the matrices.
 */
typedef struct __attribute__((aligned(4))) {
    uint64_t A[MINI_POW_MATRIX_N][MINI_POW_MATRIX_N];
    uint64_t B[MINI_POW_MATRIX_N][MINI_POW_MATRIX_N];
} mini_pow_matrix_t;

static inline OpStatus_t mini_pow_matrix_init(mini_pow_matrix_t *m)
{
    if (!m) return OP_NULL_PTR;
    // Placeholder: deterministic generation should be implemented by validator.
    // This keeps the type in place for streaming rows/cols.
    return OP_SUCCESS;
}

static inline const uint64_t *mini_pow_matrix_row(const mini_pow_matrix_t *m, uint16_t row)
{
    if (!m || row >= MINI_POW_MATRIX_N) return NULL;
    return m->A[row];
}

static inline uint64_t mini_pow_matrix_col_value(const mini_pow_matrix_t *m, uint16_t col, uint16_t k)
{
    if (!m || col >= MINI_POW_MATRIX_N || k >= MINI_POW_MATRIX_N) return 0;
    return m->B[k][col];
}

#endif // MINI_POW_MATRIX_H
