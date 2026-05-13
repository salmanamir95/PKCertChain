#ifndef MINI_POW_CHALLENGE_RECEIVE_QUEUE_H
#define MINI_POW_CHALLENGE_RECEIVE_QUEUE_H

#include "pkcertchain_config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "Proofs/MiniPoW/miniPoWChallenge.h"
#include "Proofs/MiniPoW/miniPoWChallengeQueueEntry.h"
#include "enums/OpStatus.h"

#ifndef MINI_POW_CHALLENGE_RECEIVE_QUEUE_MAX
#define MINI_POW_CHALLENGE_RECEIVE_QUEUE_MAX 128
#endif

typedef struct __attribute__((aligned(4))) {
    mini_pow_challenge_queue_entry_t entries[MINI_POW_CHALLENGE_RECEIVE_QUEUE_MAX];
    size_t count;
} mini_pow_challenge_receive_queue_t;

static inline void mini_pow_challenge_receive_queue_init(mini_pow_challenge_receive_queue_t *q)
{
    if (!q) return;
    memset(q, 0, sizeof(*q));
}

static inline OpStatus_t mini_pow_challenge_receive_queue_add(mini_pow_challenge_receive_queue_t *q,
                                                              const mini_pow_challenge_t *challenge)
{
    if (!q || !challenge) return OP_NULL_PTR;
    if (q->count >= MINI_POW_CHALLENGE_RECEIVE_QUEUE_MAX) return OP_INVALID_INPUT;

    for (size_t i = 0; i < MINI_POW_CHALLENGE_RECEIVE_QUEUE_MAX; ++i) {
        if (!q->entries[i].used) {
            q->entries[i].used = true;
            q->entries[i].challenge = *challenge;
            q->count++;
            return OP_SUCCESS;
        }
    }

    return OP_INVALID_INPUT;
}

static inline mini_pow_challenge_queue_entry_t *mini_pow_challenge_receive_queue_find(mini_pow_challenge_receive_queue_t *q, uint32_t challenge_id)
{
    if (!q) return NULL;
    for (size_t i = 0; i < MINI_POW_CHALLENGE_RECEIVE_QUEUE_MAX; ++i) {
        if (q->entries[i].used && q->entries[i].challenge.challenge_id == challenge_id) {
            return &q->entries[i];
        }
    }
    return NULL;
}

static inline OpStatus_t mini_pow_challenge_receive_queue_take(mini_pow_challenge_receive_queue_t *q,
                                                               uint32_t challenge_id,
                                                               mini_pow_challenge_t *out_challenge)
{
    if (!q || !out_challenge) return OP_NULL_PTR;
    for (size_t i = 0; i < MINI_POW_CHALLENGE_RECEIVE_QUEUE_MAX; ++i) {
        if (q->entries[i].used && q->entries[i].challenge.challenge_id == challenge_id) {
            *out_challenge = q->entries[i].challenge;
            q->entries[i].used = false;
            q->count--;
            return OP_SUCCESS;
        }
    }
    return OP_INVALID_INPUT;
}

static inline void mini_pow_challenge_receive_queue_prune_by_session(mini_pow_challenge_receive_queue_t *q, uint32_t session_id)
{
    if (!q) return;
    for (size_t i = 0; i < MINI_POW_CHALLENGE_RECEIVE_QUEUE_MAX; ++i) {
        if (q->entries[i].used && q->entries[i].challenge.session_id == session_id) {
            q->entries[i].used = false;
            if (q->count > 0) q->count--;
        }
    }
}

#endif // MINI_POW_CHALLENGE_RECEIVE_QUEUE_H
