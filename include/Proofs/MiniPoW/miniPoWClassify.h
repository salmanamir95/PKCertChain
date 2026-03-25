#ifndef MINI_POW_CLASSIFY_H
#define MINI_POW_CLASSIFY_H

#include "pkcertchain_config.h"
#include "util/Size_Offsets.h"

#include <stdint.h>
#include "blockchain/Tier.h"


static inline void mini_pow_select_row_col(uint64_t challenge_id, uint16_t *row, uint16_t *col)
{
    if (!row || !col) return;
    uint32_t n = MINI_POW_MATRIX_N;
    uint32_t r = (uint32_t)((challenge_id * 2654435761u) % n);
    uint32_t c = (uint32_t)(((challenge_id * 1597334677u) + 7u) % n);
    *row = (uint16_t)r;
    *col = (uint16_t)c;
}

static inline Tier_t mini_pow_assign_tier(uint64_t elapsed_microseconds)
{
    // Hardcoded thresholds based on 50 iter matrix multiplications.
    if (elapsed_microseconds <= 150) return TIER_SERVER;      // <= 0.15ms
    if (elapsed_microseconds <= 500) return TIER_DESKTOP;     // <= 0.5ms
    if (elapsed_microseconds <= 1500) return TIER_EDGE;       // <= 1.5ms
    return TIER_MCU;                                          // > 1.5ms
}

#endif // MINI_POW_CLASSIFY_H
