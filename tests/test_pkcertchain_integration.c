#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blockchain/pkcertchain.h"
#include "Proofs/MiniPoW/miniPoWManager.h"
#include "Proofs/MiniPoW/miniPoWSolve.h"
#include "Proofs/MiniPoW/miniPoWChallengeSendQueue.h"
#include "Proofs/MiniPoW/miniPoWAck.h"
#include "system/utilities.h"
#include "crypto/SeedUtil.h"

int main() {
    printf("--- PKCertChain & MiniPoW Integration Simulation ---\n\n");

    // 1. Initialize PKCertChain
    PKCertChain chain;
    memset(&chain, 0, sizeof(chain));
    strcpy(chain.NetworkName, "local_testnet");
    
    printf("Initializing Genesis Block...\n");
    if (Gensis_Block(&chain) != OP_SUCCESS) {
        printf("Failed to create Genesis Block.\n");
        return 1;
    }

    // 2. Local State Variables (Strictly No extra struct wrapper per requirements)
    uint32_t current_session_id = 1;
    uint256 active_block_hash;
    memset(&active_block_hash, 0, sizeof(uint256));
    
    MiniPoWManagerTracker manager;
    minipow_manager_tracker_init(&manager, current_session_id);

    for (int node_idx = 1; node_idx <= 3; ++node_idx) {
        printf("\n======================================================\n");
        // Simulate block increment logic before Node 3 joins
        if (node_idx == 3) {
            printf("Mining new block to force Session Invalidations...\n");
            block new_block;
            block_init(&new_block);
            block_set_height(&new_block, chain.index);
            // push to chain
            memcpy(&chain.blocks[chain.index++], &new_block, sizeof(block));
        }
        
        printf("--- Node %d Joining Network ---\n", node_idx);
        
        // Node Registration
        certificate cert;
        memset(&cert, 0, sizeof(certificate));
        ipv6_t test_ip; ipv6_init(&test_ip, (uint8_t[16]){100 + (uint8_t)node_idx}); cert_set_id(&cert, &test_ip);
        
        // Session Management Rule via serialization block hash analysis directly
        block *lastBlock = &chain.blocks[chain.index - 1];
        uint8_t blkData[BLOCK_SERIALIZED_SIZE];
        block_serialize(lastBlock, blkData, BLOCK_SERIALIZED_SIZE);
        uint256 current_hash;
        hash256_buffer(blkData, BLOCK_SERIALIZED_SIZE, &current_hash);
        
        if (memcmp(&current_hash, &active_block_hash, sizeof(uint256)) != 0) {
            printf("[Session Manager] Last block hash changed! Generating new Session ID.\n");
            memcpy(&active_block_hash, &current_hash, sizeof(uint256));
            current_session_id++;
            minipow_manager_tracker_init(&manager, current_session_id);
        } else {
            printf("[Session Manager] Last block hash unchanged! Reusing Session ID %u.\n", current_session_id);
        }
        
        // Challenge Assignment
        uint32_t challengeID = chain.next_challenge_id++;
        printf("[Challenge Assignment] Node %d assigned challenge ID: %u\n", node_idx, challengeID);
        
        // MiniPow Matrix generation
        printf("Generating Constraints Matrices (CSPRNG)...\n");
        mini_pow_Matrix *matrices = calloc(1, sizeof(mini_pow_Matrix));
        if (construct_mini_pow_matrices(&cert, &active_block_hash, current_session_id, challengeID, matrices) != OP_SUCCESS) {
            printf("Matrix generation failed.\n");
            return 1;
        }
        
        // Setup Queues and Miner Solvers
        mini_pow_challenge_queue_t sendQueue;
        mini_pow_challenge_queue_init(&sendQueue);
        
        mini_pow_solve_t receiverSolve;
        mini_pow_solve_init(&receiverSolve);
        
        printf("Starting Miner Work Loop...\n");
        
        // Loop interactions exactly
        for (uint32_t i = 0; i < MINI_POW_MATRIX_N; ++i) {
            // Manager Sends 
            minipow_manager_send(&manager, challengeID);
            
            // Constructs structural vector format natively via queues
            mini_pow_challenge_t ch;
            mini_pow_challenge_init(&ch);
            ch.challenge_id = challengeID;
            ch.session_id = current_session_id;
            ch.iteration = i;
            for(size_t k = 0; k < MINI_POW_MATRIX_N; ++k) {
                ch.columnOfA[k] = matrices->A[k][i];
                ch.rowOfB[k] = matrices->B[i][k];
            }
            mini_pow_challenge_queue_add(&sendQueue, &ch);
            
            // Miner Receives
            mini_pow_challenge_t rx_ch;
            if (mini_pow_challenge_queue_take(&sendQueue, challengeID, &rx_ch) == OP_SUCCESS) {
                mini_pow_solve_update(&receiverSolve, &rx_ch);
                
                // Miner explicit ACK
                MiniPoW_ACK ack = { .sessionID = current_session_id, .challengeID = challengeID, .ACK = true };
                
                // Manager explicitly receives
                if (ack.ACK && ack.sessionID == current_session_id && ack.challengeID == challengeID) {
                    minipow_manager_receive_ack(&manager);
                }
            } else {
                 printf("Queue fetch miss!\n");
            }
        }
        
        SolvedMatricPoW *solvedMatrix = calloc(1, sizeof(SolvedMatricPoW));
        solved_matric_pow_init(solvedMatrix);
        solvedMatrix->session_id = current_session_id;
        solvedMatrix->challenge_id = challengeID;
        memcpy(solvedMatrix->Matrix, receiverSolve.resultMatrix, sizeof(solvedMatrix->Matrix));
        
        // pkcertchain verification pipeline
        mini_pow_result result = minipow_manager_finalize(&manager, solvedMatrix, matrices);
        
        printf("\n--- Validation & Result for Node %d ---\n", node_idx);
        printf("Is Valid: %s\n", result.isValid ? "true" : "false");
        printf("Hardware Tier Assigned: %d\n", result.tier);
        printf("Session ID: %u | Challenge ID: %u\n", result.sessionid, result.challengeid);
        
        // Blockchain State mapping locally
        if (result.isValid) {
            double elapsed = manager.timeTracker.cumulative_duration / 1000000.0;
            if (chain.avg_solve_time_seconds > 0) {
                chain.avg_solve_time_seconds = (chain.avg_solve_time_seconds + elapsed) / 2.0;
            } else {
                chain.avg_solve_time_seconds = elapsed;
            }
        }
        printf("Updated Chain Avg Solve Time: %.6f seconds\n", chain.avg_solve_time_seconds);
        
        // Clean up matrices for iteration
        free(solvedMatrix);
        free(matrices);
    }
    
    printf("\n======================================================\n");
    printf("Integration Simulation Completed Successfully.\n");
    return 0;
}
