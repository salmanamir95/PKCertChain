#ifndef MINI_POW_MANAGER_H
#define MINI_POW_MANAGER_H

#include <stdio.h>
#include "protocol/proofs/mini_pow/mini_pow_challenge_t.h"
#include "Proofs/MiniPoW/miniPoWVerify_ops.h"
#include "Proofs/MiniPoW/miniPoWClassify_ops.h"
#include "protocol/proofs/mini_pow/mini_pow_Ack_t.h"
#include "protocol/proofs/mini_pow/mini_pow_ManagerTracker_t.h"
#include "protocol/proofs/mini_pow/mini_pow_Result_t.h"

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
