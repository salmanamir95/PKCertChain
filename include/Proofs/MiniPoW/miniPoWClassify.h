#ifndef MINI_POW_CLASSIFY_H
#define MINI_POW_CLASSIFY_H

#include "pkcertchain_config.h"

#include <stdint.h>
#include "blockchain/Tier.h"

#define MINI_POW_MATRIX_N 1000

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
