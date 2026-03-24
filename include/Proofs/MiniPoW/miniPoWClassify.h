#ifndef MINI_POW_CLASSIFY_H
#define MINI_POW_CLASSIFY_H

#include "pkcertchain_config.h"

#include <stdint.h>
#include "blockchain/Tier.h"

#define MINI_POW_MATRIX_N 1000

static inline void mini_pow_select_row_col(uint64_t challenge_id, uint16_t *row, uint16_t *col)
{
    if (!row || !col) return;
    uint32_t n = MINI_POW_MATRIX_N;
    uint32_t r = (uint32_t)((challenge_id * 2654435761u) % n);
    uint32_t c = (uint32_t)(((challenge_id * 1597334677u) + 7u) % n);
    *row = (uint16_t)r;
    *col = (uint16_t)c;
}

static inline Tier_t mini_pow_assign_tier(double avg_seconds, uint64_t elapsed_seconds)
{
    if (avg_seconds <= 0.0) return TIER_INVALID;
    double elapsed = (double)elapsed_seconds;

    if (elapsed <= 0.25 * avg_seconds) return TIER_SERVER;
    if (elapsed <= 0.60 * avg_seconds) return TIER_DESKTOP;
    if (elapsed <= 1.50 * avg_seconds) return TIER_EDGE;
    if (elapsed <= 3.00 * avg_seconds) return TIER_MCU;
    return TIER_INVALID;
}

#endif // MINI_POW_CLASSIFY_H
