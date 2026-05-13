#ifndef MINI_POW_CHALLENGE_H
#define MINI_POW_CHALLENGE_H



#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "shared/core/enums/OpStatus.h"
#include "shared/protocol/proofs/mini_pow/mini_pow_Classify_t.h"
#include "shared/core/Global_Size_Offsets.h"

#define MINI_POW_CHALLENGE_INLINE static inline __attribute__((always_inline))

/*
 * MiniPoW Challenge structure
 * Contains the specific row of Matrix A and column of Matrix B that the miner must multiply,
 * along with identifiers.
//  */
// typedef struct __attribute__((aligned(4))) {
//     uint32_t challenge_id;
//     uint32_t session_id;
//     uint32_t iteration;
//     uint16_t columnOfA[MINI_POW_MATRIX_N];
//     uint16_t rowOfB[MINI_POW_MATRIX_N];
// } mini_pow_challenge_t;


MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_init(mini_pow_challenge_t *pow)
{
    if (!pow) return;
    pow->challenge_id = 0;
    pow->session_id = 0;
    pow->iteration = 0;
    memset(pow->columnOfA, 0, sizeof(pow->columnOfA));
    memset(pow->rowOfB, 0, sizeof(pow->rowOfB));
}

#endif // MINI_POW_CHALLENGE_H
