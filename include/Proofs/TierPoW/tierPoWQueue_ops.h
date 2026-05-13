#ifndef TIER_POW_QUEUE_H
#define TIER_POW_QUEUE_H



#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "Proofs/TierPoW/tierPoWSession.h"
#include "blockchain/block.h"
#include "core/enums/OpStatus.h"

#ifndef TIER_POW_QUEUE_MAX
#define TIER_POW_QUEUE_MAX 128
#endif

typedef struct __attribute__((aligned(4))) {
    bool used;
    tier_pow_session_t session;
    block candidate;
} tier_pow_queue_entry_t;

typedef struct __attribute__((aligned(4))) {
    tier_pow_queue_entry_t entries[TIER_POW_QUEUE_MAX];
    size_t count;
} tier_pow_queue_t;

static inline void tier_pow_queue_init(tier_pow_queue_t *q)
{
    if (!q) return;
    memset(q, 0, sizeof(*q));
}

static inline OpStatus_t tier_pow_queue_add(tier_pow_queue_t *q,
                                            const tier_pow_session_t *session,
                                            const block *candidate)
{
    if (!q || !session || !candidate) return OP_NULL_PTR;
    if (q->count >= TIER_POW_QUEUE_MAX) return OP_INVALID_INPUT;

    for (size_t i = 0; i < TIER_POW_QUEUE_MAX; ++i) {
        if (!q->entries[i].used) {
            q->entries[i].used = true;
            q->entries[i].session = *session;
            block_copy(&q->entries[i].candidate, candidate);
            q->count++;
            return OP_SUCCESS;
        }
    }

    return OP_INVALID_INPUT;
}

static inline tier_pow_queue_entry_t *tier_pow_queue_find(tier_pow_queue_t *q, uint64_t challenge_id)
{
    if (!q) return NULL;
    for (size_t i = 0; i < TIER_POW_QUEUE_MAX; ++i) {
        if (q->entries[i].used && q->entries[i].session.challenge.challenge_id == challenge_id) {
            return &q->entries[i];
        }
    }
    return NULL;
}

static inline OpStatus_t tier_pow_queue_take(tier_pow_queue_t *q,
                                             uint64_t challenge_id,
                                             tier_pow_session_t *out_session,
                                             block *out_candidate)
{
    if (!q || !out_session || !out_candidate) return OP_NULL_PTR;
    for (size_t i = 0; i < TIER_POW_QUEUE_MAX; ++i) {
        if (q->entries[i].used && q->entries[i].session.challenge.challenge_id == challenge_id) {
            *out_session = q->entries[i].session;
            block_copy(out_candidate, &q->entries[i].candidate);
            q->entries[i].used = false;
            q->count--;
            return OP_SUCCESS;
        }
    }
    return OP_INVALID_INPUT;
}

static inline void tier_pow_queue_prune_by_index(tier_pow_queue_t *q, uint32_t target_index)
{
    if (!q) return;
    for (size_t i = 0; i < TIER_POW_QUEUE_MAX; ++i) {
        if (q->entries[i].used && q->entries[i].session.target_index == target_index) {
            q->entries[i].used = false;
            if (q->count > 0) q->count--;
        }
    }
}

#endif // TIER_POW_QUEUE_H
