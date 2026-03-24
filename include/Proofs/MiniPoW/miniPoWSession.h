#ifndef MINI_POW_SESSION_H
#define MINI_POW_SESSION_H

#include "pkcertchain_config.h"

#include <stdint.h>
#include <string.h>
#include "Proofs/MiniPoW/miniPoWChallenge.h"

typedef struct __attribute__((aligned(4))) {
    mini_pow_challenge_t challenge;
    uint64_t issued_time_seconds;
    uint64_t received_time_seconds;
    uint32_t target_index;
    uint64_t total_elapsed_ms;
    uint16_t iterations_done;
} mini_pow_session_t;

static inline void mini_pow_session_init(mini_pow_session_t *session)
{
    if (!session) return;
    memset(session, 0, sizeof(*session));
}

#endif // MINI_POW_SESSION_H
