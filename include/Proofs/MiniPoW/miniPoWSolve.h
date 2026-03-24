#ifndef MINI_POW_SOLVE_H
#define MINI_POW_SOLVE_H

#include "pkcertchain_config.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "Proofs/MiniPoW/miniPoWChallenge.h"
#include "Proofs/MiniPoW/miniPoWMatrix.h"
#include "datatype/uint256_t.h"
#include "util/To_BO_BE_Pimitives.h"
#include "util/To_BO_Def_Primitives.h"
#include "util/Size_Offsets.h"
#include "datatype/OpStatus.h"

#define MINI_POW_SOLVE_INLINE static inline __attribute__((always_inline))

#define MINI_POW_SOLVE_SERIALIZED_SIZE MINI_POW_SOLVE_SIZE

typedef struct __attribute__((aligned(4)))
{
    uint16_t row;            // 2 bytes
    uint16_t col;            // 2 bytes
    uint16_t iteration;      // 2 bytes
    uint64_t result;         // 8 bytes
    uint64_t elapsed_ms;     // 8 bytes
    uint64_t challenge_id;   // 8 bytes
} mini_pow_solve_t;

MINI_POW_SOLVE_INLINE void mini_pow_solve_init(mini_pow_solve_t *pow)
{
    pow->row = 0;
    pow->col = 0;
    pow->iteration = 0;
    pow->result = 0;
    pow->elapsed_ms = 0;
    pow->challenge_id = 0;
}

MINI_POW_SOLVE_INLINE OpStatus_t mini_pow_solve_serialize(const mini_pow_solve_t *pow, uint8_t *out, size_t out_size)
{
    if (!pow || !out) return OP_NULL_PTR;
    if (out_size < MINI_POW_SOLVE_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    serialize_u16_be(pow->row, out);
    serialize_u16_be(pow->col, out + UINT16_SIZE);
    serialize_u16_be(pow->iteration, out + 2 * UINT16_SIZE);
    serialize_u64_be(pow->result, out + 3 * UINT16_SIZE);
    serialize_u64_be(pow->elapsed_ms, out + 3 * UINT16_SIZE + UINT64_SIZE);
    serialize_u64_be(pow->challenge_id, out + 3 * UINT16_SIZE + 2 * UINT64_SIZE);
    return OP_SUCCESS;
}

MINI_POW_SOLVE_INLINE OpStatus_t mini_pow_solve_deserialize(const uint8_t *in, size_t in_size, mini_pow_solve_t *pow)
{
    if (!pow || !in) return OP_NULL_PTR;
    if (in_size < MINI_POW_SOLVE_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    deserialize_u16_be(in, &pow->row, sizeof(uint16_t));
    deserialize_u16_be(in + UINT16_SIZE, &pow->col, sizeof(uint16_t));
    deserialize_u16_be(in + 2 * UINT16_SIZE, &pow->iteration, sizeof(uint16_t));
    deserialize_u64_be(in + 3 * UINT16_SIZE, &pow->result, sizeof(uint64_t));
    deserialize_u64_be(in + 3 * UINT16_SIZE + UINT64_SIZE, &pow->elapsed_ms, sizeof(uint64_t));
    deserialize_u64_be(in + 3 * UINT16_SIZE + 2 * UINT64_SIZE, &pow->challenge_id, sizeof(uint64_t));
    return OP_SUCCESS;
}

MINI_POW_SOLVE_INLINE uint64_t mini_pow_compute_element_from_matrices(const mini_pow_matrix_t *m,
                                                                      uint16_t row,
                                                                      uint16_t col)
{
    uint64_t acc = 0;
    for (uint16_t k = 0; k < MINI_POW_MATRIX_N; ++k) {
        uint64_t a = m->A[row][k];
        uint64_t b = m->B[k][col];
        acc += (a * b);
    }
    return acc;
}

MINI_POW_SOLVE_INLINE OpStatus_t mini_pow_solve_compute(const mini_pow_challenge_t *pow,
                                                        const mini_pow_matrix_t *m,
                                                        uint64_t elapsed_ms,
                                                        mini_pow_solve_t *out)
{
    if (!pow || !m || !out) return OP_NULL_PTR;
    mini_pow_solve_init(out);

    out->row = pow->row;
    out->col = pow->col;
    out->iteration = pow->iteration;
    out->challenge_id = pow->challenge_id;
    out->elapsed_ms = elapsed_ms;
    out->result = mini_pow_compute_element_from_matrices(m, pow->row, pow->col);
    return OP_SUCCESS;
}

#endif // MINI_POW_SOLVE_H
