#ifndef MINI_POW_QUEUE_H
#define MINI_POW_QUEUE_H

#include "pkcertchain_config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "Proofs/MiniPoW/miniPoWSession.h"
#include "blockchain/block.h"
#include "datatype/OpStatus.h"

#ifndef MINI_POW_QUEUE_MAX
#define MINI_POW_QUEUE_MAX 128
#endif

typedef struct __attribute__((aligned(4))) {
    bool used;
    mini_pow_session_t session;
    block candidate;
    uint64_t total_elapsed_ms;
    uint16_t iterations_done;
} mini_pow_queue_entry_t;

typedef struct __attribute__((aligned(4))) {
    mini_pow_queue_entry_t entries[MINI_POW_QUEUE_MAX];
    size_t count;
} mini_pow_queue_t;

static inline void mini_pow_queue_init(mini_pow_queue_t *q)
{
    if (!q) return;
    memset(q, 0, sizeof(*q));
}

static inline OpStatus_t mini_pow_queue_add(mini_pow_queue_t *q,
                                            const mini_pow_session_t *session,
                                            const block *candidate)
{
    if (!q || !session || !candidate) return OP_NULL_PTR;
    if (q->count >= MINI_POW_QUEUE_MAX) return OP_INVALID_INPUT;

    for (size_t i = 0; i < MINI_POW_QUEUE_MAX; ++i) {
        if (!q->entries[i].used) {
            q->entries[i].used = true;
            q->entries[i].session = *session;
            block_copy(&q->entries[i].candidate, candidate);
            q->entries[i].total_elapsed_ms = 0;
            q->entries[i].iterations_done = 0;
            q->count++;
            return OP_SUCCESS;
        }
    }

    return OP_INVALID_INPUT;
}

static inline mini_pow_queue_entry_t *mini_pow_queue_find(mini_pow_queue_t *q, uint64_t challenge_id)
{
    if (!q) return NULL;
    for (size_t i = 0; i < MINI_POW_QUEUE_MAX; ++i) {
        if (q->entries[i].used && q->entries[i].session.challenge.challenge_id == challenge_id) {
            return &q->entries[i];
        }
    }
    return NULL;
}

static inline OpStatus_t mini_pow_queue_take(mini_pow_queue_t *q,
                                             uint64_t challenge_id,
                                             mini_pow_session_t *out_session,
                                             block *out_candidate)
{
    if (!q || !out_session || !out_candidate) return OP_NULL_PTR;
    for (size_t i = 0; i < MINI_POW_QUEUE_MAX; ++i) {
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

static inline void mini_pow_queue_prune_by_index(mini_pow_queue_t *q, uint32_t target_index)
{
    if (!q) return;
    for (size_t i = 0; i < MINI_POW_QUEUE_MAX; ++i) {
        if (q->entries[i].used && q->entries[i].session.target_index == target_index) {
            q->entries[i].used = false;
            if (q->count > 0) q->count--;
        }
    }
}

static inline OpStatus_t mini_pow_queue_record_timing(mini_pow_queue_t *q,
                                                      uint64_t challenge_id,
                                                      uint64_t elapsed_ms,
                                                      double *out_avg_ms)
{
    if (!q) return OP_NULL_PTR;
    for (size_t i = 0; i < MINI_POW_QUEUE_MAX; ++i) {
        if (q->entries[i].used && q->entries[i].session.challenge.challenge_id == challenge_id) {
            q->entries[i].total_elapsed_ms += elapsed_ms;
            if (q->entries[i].iterations_done < MINI_POW_MATRIX_N) {
                q->entries[i].iterations_done += 1;
            }
            if (out_avg_ms) {
                uint16_t done = q->entries[i].iterations_done;
                if (done > 0) {
                    *out_avg_ms = (double)q->entries[i].total_elapsed_ms / (double)done;
                }
            }
            return OP_SUCCESS;
        }
    }
    return OP_INVALID_INPUT;
}

#endif // MINI_POW_QUEUE_H
