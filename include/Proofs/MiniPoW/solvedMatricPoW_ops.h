#ifndef SOLVED_MATRIC_POW_H
#define SOLVED_MATRIC_POW_H


#include "core/Global_Size_Offsets.h"
#include <stdint.h>
#include <string.h>
#include "protocol/proofs/mini_pow/mini_pow_Classify_t.h"

#ifndef SOLVED_MATRIC_POW_INLINE
#define SOLVED_MATRIC_POW_INLINE static inline __attribute__((always_inline))
#endif

/*
 * Final solved matrix returned by the miner along with the puzzle identifiers.
 * Using uint32_t to safely store the sum of the outer products.
 */
typedef struct __attribute__((aligned(4))) {
    uint32_t challenge_id;
    uint32_t session_id;
    uint32_t Matrix[MINI_POW_MATRIX_N][MINI_POW_MATRIX_N];
} SolvedMatricPoW;

SOLVED_MATRIC_POW_INLINE void solved_matric_pow_init(SolvedMatricPoW *solved)
{
    if (!solved) return;
    solved->challenge_id = 0;
    solved->session_id = 0;
    memset(solved->Matrix, 0, sizeof(solved->Matrix));
}

#endif // SOLVED_MATRIC_POW_H
