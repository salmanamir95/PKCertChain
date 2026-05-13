#ifndef POW_MANAGER_H
#define POW_MANAGER_H



#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>

#include "blockchain/block.h"
#include "blockchain/pkcertchain_ops.h"
#include "shared/proofs/tier_pow/tierPoWChallenge.h"
#include "shared/proofs/tier_pow/tierPoWSolve.h"
#include "shared/proofs/tier_pow/tierPoWVerify.h"
#include "shared/proofs/tier_pow/tierPoWResult.h"
#include "shared/core/enums/OpStatus.h"

// typedef struct {
//     PKCertChain *chain;
//     uint8_t tier;
//     MiniPowResult *miniResult;
//     tier_pow_challenge_t challenge;
//     tier_pow_solve_t solve;
//     double solve_time_seconds;
// } PowManager;

static inline uint8_t bayesian_update(uint8_t current_complexity, double solve_time_seconds) {
    const double target_time = 600.0;
    if (solve_time_seconds <= 0.0) solve_time_seconds = 0.1;
    
    double next = current_complexity;
    
    if (target_time < solve_time_seconds) {
        double ratio = (solve_time_seconds - target_time) / target_time;
        next -= (current_complexity * ratio);
    } else if (target_time > solve_time_seconds) {
        double ratio = (target_time - solve_time_seconds) / target_time;
        next += (current_complexity * ratio);
    }
    
    if (next > 255.0) return 255;
    if (next < 1.0) return 1;
    return (uint8_t)next;
}

static inline double get_monotonic_time_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static inline OpStatus_t generate_tier_pow_challenge(block *blk,
                                                     uint8_t complexity,
                                                     tier_pow_challenge_t *pow)
{
    uint8_t buf[CERT_SIZE + UINT256_SIZE + UINT64_SIZE + UINT64_SIZE + 4 * UINT8_SIZE];
    const size_t packed_len = sizeof(buf);

    if (!blk || !pow) return OP_NULL_PTR;

    uint256_serialize_be(&blk->cert.pubSignKey, buf, UINT256_SIZE);
    uint256_serialize_be(&blk->cert.pubEncKey, buf + UINT256_SIZE, UINT256_SIZE);
    buf[CERT_SIZE - 1] = blk->cert.id;

    uint256_serialize_be(&blk->prevHash, buf + CERT_SIZE, UINT256_SIZE);
    serialize_u64_be(blk->height, buf + CERT_SIZE + UINT256_SIZE);
    serialize_u64_be(blk->timestamp, buf + CERT_SIZE + UINT256_SIZE + UINT64_SIZE);
    serialize_u8(blk->tier, buf + CERT_SIZE + UINT256_SIZE + 2 * UINT64_SIZE);

    hash256_buffer(buf, packed_len, &pow->challenge);

    pow->complexity = complexity;

    return OP_SUCCESS;
}

static inline OpStatus_t PowManager_Run(PowManager *manager, block *currentBlock) {
    uint32_t lastIndex = 0;
    uint8_t complexity = 0;

    switch(manager->tier) {
        case TIER_MCU: 
            lastIndex = manager->chain->lastMCUBlockIndex; 
            complexity = manager->chain->MCUComplexity; 
            break;
        case TIER_SERVER: 
            lastIndex = manager->chain->lastServerBlockIndex; 
            complexity = manager->chain->ServerComplexity; 
            break;
        case TIER_DESKTOP: 
            lastIndex = manager->chain->lastDesktopBlockIndex; 
            complexity = manager->chain->DesktopComplexity; 
            break;
        case TIER_EDGE: 
            lastIndex = manager->chain->lastEdgeBlockIndex; 
            complexity = manager->chain->EdgeComplexity; 
            break;
        default: 
            return OP_INVALID_INPUT;
    }

    block *refBlock = &manager->chain->blocks[lastIndex];

    generate_tier_pow_challenge(refBlock, complexity, &manager->challenge);

    tier_pow_solve_init(&manager->solve);
    tier_pow_solve_t *solve_ptr = &manager->solve;
    
    // Simulate / execute the real work
    double start_time = get_monotonic_time_sec();
    // To prevent total system freezing in integration testing if complexity == 100,
    // we do a standard solve run. However, 100 leading zeros is unreachable quickly.
    // If the system test modifies complexity to manageable, this will return quickly.
    tier_pow_solve_challenge(&manager->challenge, &solve_ptr); 
    double end_time = get_monotonic_time_sec();
    
    manager->solve_time_seconds = end_time - start_time;

    if (!solve_ptr || !isValidTierChallenge(&manager->challenge, &manager->solve)) {
        return OP_INVALID_INPUT;
    }

    switch(manager->tier) {
        case TIER_MCU: 
            manager->chain->MCUComplexity = bayesian_update(manager->chain->MCUComplexity, manager->solve_time_seconds); 
            break;
        case TIER_SERVER: 
            manager->chain->ServerComplexity = bayesian_update(manager->chain->ServerComplexity, manager->solve_time_seconds); 
            break;
        case TIER_DESKTOP: 
            manager->chain->DesktopComplexity = bayesian_update(manager->chain->DesktopComplexity, manager->solve_time_seconds); 
            break;
        case TIER_EDGE: 
            manager->chain->EdgeComplexity = bayesian_update(manager->chain->EdgeComplexity, manager->solve_time_seconds); 
            break;
    }

    if (manager->miniResult) {
        currentBlock->miniPowResult = *(manager->miniResult);
    }

    TierPowResult tr;
    tierpowresult_init(&tr);
    tr.tier = (Tier_t)manager->tier;
    tr.challenge = manager->challenge;
    tr.solve = manager->solve;
    tr.time_taken = manager->solve_time_seconds;
    
    currentBlock->tierPoWResult = tr;

    switch(manager->tier) {
        case TIER_MCU: manager->chain->lastMCUBlockIndex = currentBlock->height; break;
        case TIER_SERVER: manager->chain->lastServerBlockIndex = currentBlock->height; break;
        case TIER_DESKTOP: manager->chain->lastDesktopBlockIndex = currentBlock->height; break;
        case TIER_EDGE: manager->chain->lastEdgeBlockIndex = currentBlock->height; break;
    }

    return OP_SUCCESS;
}

static inline OpStatus_t PKCertChain_AddBlockWithPoW(PKCertChain *chain, MiniPowResult *miniResult, Tier_t tier)
{
    if (!chain) return OP_NULL_PTR;
    
    block *blk = &chain->blocks[chain->index];
    block_init(blk);
    blk->height = chain->index;
    blk->tier = tier;

    PowManager manager;
    manager.chain = chain;
    manager.tier = tier;
    manager.miniResult = miniResult;

    OpStatus_t st = PowManager_Run(&manager, blk);
    if(st != OP_SUCCESS) return st;

    chain->index++;
    return OP_SUCCESS;
}

#endif // POW_MANAGER_H
