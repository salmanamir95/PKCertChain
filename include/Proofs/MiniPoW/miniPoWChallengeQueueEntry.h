#ifndef MINI_POW_CHALLENGE_QUEUE_ENTRY_H
#define MINI_POW_CHALLENGE_QUEUE_ENTRY_H

#include "pkcertchain_config.h"

#include <stdbool.h>
#include "Proofs/MiniPoW/miniPoWChallenge.h"

/*
 * MiniPoW Challenge Queue Entry
 * Holds a challenge struct and tracks if the slot is occupied.
 */
typedef struct __attribute__((aligned(4))) {
    bool used;
    mini_pow_challenge_t challenge;
} mini_pow_challenge_queue_entry_t;

#endif // MINI_POW_CHALLENGE_QUEUE_ENTRY_H
