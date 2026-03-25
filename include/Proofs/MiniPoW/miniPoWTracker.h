#ifndef MINI_POW_TRACKER_H
#define MINI_POW_TRACKER_H

#include "pkcertchain_config.h"
#include <stdint.h>
#include <string.h>
#include <time.h>

#ifndef MINI_POW_TRACKER_INLINE
#define MINI_POW_TRACKER_INLINE static inline __attribute__((always_inline))
#endif

/*
 * MiniPowTracker
 * Used to track the start time of a challenge for a specific miner
 * using Linux monotonic time (uint64_t).
 */
typedef struct __attribute__((aligned(4))) {
    uint32_t challenge_id;
    uint32_t session_id;
    uint64_t time; // Linux monotonic time (in microseconds)
} MiniPowTracker;

MINI_POW_TRACKER_INLINE void mini_pow_tracker_init(MiniPowTracker *tracker)
{
    if (!tracker) return;
    tracker->challenge_id = 0;
    tracker->session_id = 0;
    tracker->time = 0;
}

MINI_POW_TRACKER_INLINE void mini_pow_tracker_update_timer(MiniPowTracker *tracker)
{
    if (!tracker) return;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        // Store as microseconds for high-resolution timing
        tracker->time = (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000ULL);
    }
}

#endif // MINI_POW_TRACKER_H
