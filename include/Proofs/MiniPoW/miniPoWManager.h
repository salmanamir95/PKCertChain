#ifndef MINI_POW_MANAGER_H
#define MINI_POW_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "Proofs/MiniPoW/miniPoWChallenge.h"
#include "Proofs/MiniPoW/solvedMatricPoW.h"
#include "Proofs/MiniPoW/miniPoWTracker.h"
#include "Proofs/MiniPoW/miniPoWVerify.h"
#include "Proofs/MiniPoW/miniPoWClassify.h"

// The ACK sent by the receiver after solving an iteration (0 to 998).
typedef struct {
    uint32_t sessionID;
    uint32_t challengeID;
    bool ACK;
} MiniPoW_ACK;

// Manager Tracker for a session
typedef struct {
    uint32_t sessionID;
    uint32_t currentIteration;
    MiniPowTracker timeTracker;
} MiniPoWManagerTracker;

// The final result returned by the manager
typedef struct {
    uint32_t challengeid;
    uint32_t sessionid;
    const mini_pow_Matrix *minipowmatrix;
    const SolvedMatricPoW *solvedmatrix;
    Tier_t tier;
    bool isValid;
} mini_pow_result;

static inline void minipow_manager_tracker_init(MiniPoWManagerTracker *mgr, uint32_t session_id) {
    if (!mgr) return;
    mgr->sessionID = session_id;
    mgr->currentIteration = 0;
    mini_pow_tracker_init(&mgr->timeTracker);
    mgr->timeTracker.session_id = session_id;
}

static inline void minipow_manager_send(MiniPoWManagerTracker *mgr, uint32_t challenge_id) {
    if (!mgr) return;
    mgr->timeTracker.challenge_id = challenge_id;
    mini_pow_tracker_update_start(&mgr->timeTracker);
}

static inline void minipow_manager_receive_ack(MiniPoWManagerTracker *mgr) {
    if (!mgr) return;
    mini_pow_tracker_update_receive(&mgr->timeTracker);
    
    uint64_t duration = mgr->timeTracker.recent_receive_time > mgr->timeTracker.recent_start_time ?
                        (mgr->timeTracker.recent_receive_time - mgr->timeTracker.recent_start_time) : 0;
    
    printf("Iteration %u duration: %lu us (Cumulative: %lu us)\n", 
           mgr->currentIteration, duration, mgr->timeTracker.cumulative_duration);
           
    mgr->currentIteration++;
}

static inline mini_pow_result minipow_manager_finalize(MiniPoWManagerTracker *mgr, 
                                                       const SolvedMatricPoW *solved, 
                                                       const mini_pow_Matrix *matrices) {
    mini_pow_result result;
    result.challengeid = mgr->timeTracker.challenge_id;
    result.sessionid = mgr->sessionID;
    result.minipowmatrix = matrices;
    result.solvedmatrix = solved;
    result.isValid = mini_pow_verify(solved, matrices);
    
    if (result.isValid) {
        result.tier = mini_pow_assign_tier(mgr->timeTracker.cumulative_duration);
    } else {
        result.tier = TIER_INVALID;
    }
    
    return result;
}

#endif // MINI_POW_MANAGER_H
