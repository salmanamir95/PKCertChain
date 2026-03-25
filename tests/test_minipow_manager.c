#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Proofs/MiniPoW/miniPoWManager.h"
#include "Proofs/MiniPoW/miniPoWChallengeSendQueue.h"
#include "Proofs/MiniPoW/miniPoWChallengeReceiveQueue.h"
#include "Proofs/MiniPoW/miniPoWSolve.h"
#include "Proofs/MiniPoW/miniPoWMatrix.h"

int main() {
    printf("Initializing MiniPoW Manager framework...\n");
    
    uint32_t sessionID = 101;
    
    // 1. Manager state initialization
    MiniPoWManagerTracker manager;
    minipow_manager_tracker_init(&manager, sessionID);
    
    // 2. Queues for asynchronous simulation
    mini_pow_challenge_queue_t sendQueue;
    mini_pow_challenge_queue_init(&sendQueue);
    
    // 3. Receiver solver initialization (allocated on heap to avoid stack overflow)
    mini_pow_solve_t *receiverSolve = calloc(1, sizeof(mini_pow_solve_t));
    mini_pow_solve_init(receiverSolve);
    
    // Live matrices generation for robust testing
    mini_pow_Matrix *matrices = calloc(1, sizeof(mini_pow_Matrix));
    certificate dummy_cert;
    memset(&dummy_cert, 0, sizeof(dummy_cert));
    uint256 dummy_hash;
    memset(&dummy_hash, 0, sizeof(dummy_hash));

    printf("Generating MiniPoW Matrices via CSPRNG...\n");
    if(construct_mini_pow_matrices(&dummy_cert, &dummy_hash, sessionID, 12345, matrices) != OP_SUCCESS){
        printf("Failed to generate matrices natively!\n");
        return 1;
    }
    
    printf("Starting Session %u (Iterations: %u)\n", sessionID, MINI_POW_MATRIX_N);
    
    for (uint32_t i = 0; i < MINI_POW_MATRIX_N; ++i) {
        // --- SENDER (Manager) ---
        uint32_t challengeID = 1000 + i;
        
        mini_pow_challenge_t challenge;
        mini_pow_challenge_init(&challenge);
        challenge.challenge_id = challengeID;
        challenge.session_id = sessionID;
        challenge.iteration = i;
        
        // Populate the respective column and row correctly
        for(size_t k = 0; k < MINI_POW_MATRIX_N; ++k) {
            challenge.columnOfA[k] = matrices->A[k][i]; // i-th column
            challenge.rowOfB[k] = matrices->B[i][k];    // i-th row
        }
        
        // Push the challenge and update sender time
        mini_pow_challenge_queue_add(&sendQueue, &challenge);
        minipow_manager_send(&manager, challengeID);
        
        // --- RECEIVER (Miner) ---
        mini_pow_challenge_t receivedChallenge;
        if(mini_pow_challenge_queue_take(&sendQueue, challengeID, &receivedChallenge) == OP_SUCCESS) {
            
            // Incrementally solve the matrix chunk
            mini_pow_solve_update(receiverSolve, &receivedChallenge);
            
            if (i < MINI_POW_MATRIX_N - 1) {
                // Not final iteration: Generate simple ACK
                MiniPoW_ACK ack = { .sessionID = sessionID, .challengeID = challengeID, .ACK = true };
                
                // --- MANAGER ---
                // Process the ACK and track duration
                if (ack.ACK && ack.sessionID == sessionID && ack.challengeID == challengeID) {
                    minipow_manager_receive_ack(&manager);
                }
            } else {
                // Final iteration: Return entire solved matrix (no simple ACK)
                SolvedMatricPoW *solvedMatrix = calloc(1, sizeof(SolvedMatricPoW));
                solved_matric_pow_init(solvedMatrix);
                solvedMatrix->session_id = sessionID;
                solvedMatrix->challenge_id = challengeID;
                memcpy(solvedMatrix->Matrix, receiverSolve->resultMatrix, sizeof(solvedMatrix->Matrix));
                
                // --- MANAGER ---
                minipow_manager_receive_ack(&manager); // Log final duration
                
                mini_pow_result result = minipow_manager_finalize(&manager, solvedMatrix, matrices);
                
                printf("\n--- mini_pow_result ---\n");
                printf("Session ID: %u\n", result.sessionid);
                printf("Challenge ID: %u\n", result.challengeid);
                printf("Is Valid: %s\n", result.isValid ? "true" : "false");
                printf("Tier: %d\n", result.tier);

                // printf("\nMatrix A (%dx%d):\n", MINI_POW_MATRIX_N, MINI_POW_MATRIX_N);
                // for(size_t r=0; r<MINI_POW_MATRIX_N; ++r) {
                //     for(size_t c=0; c<MINI_POW_MATRIX_N; ++c) {
                //         printf("%04x ", result.minipowmatrix->A[r][c]);
                //     }
                //     printf("\n");
                // }

                // printf("\nMatrix B (%dx%d):\n", MINI_POW_MATRIX_N, MINI_POW_MATRIX_N);
                // for(size_t r=0; r<MINI_POW_MATRIX_N; ++r) {
                //     for(size_t c=0; c<MINI_POW_MATRIX_N; ++c) {
                //         printf("%04x ", result.minipowmatrix->B[r][c]);
                //     }
                //     printf("\n");
                // }

                // printf("\nSolved Matrix (%dx%d):\n", MINI_POW_MATRIX_N, MINI_POW_MATRIX_N);
                // for(size_t r=0; r<MINI_POW_MATRIX_N; ++r) {
                //     for(size_t c=0; c<MINI_POW_MATRIX_N; ++c) {
                //         printf("%08x ", result.solvedmatrix->Matrix[r][c]);
                //     }
                //     printf("\n");
                // }
                printf("-----------------------\n");
                
                free(solvedMatrix);
            }
        } else {
            printf("Error: Challenge not found in queue.\n");
            break;
        }
    }
    
    free(receiverSolve);
    free(matrices);
    
    return 0;
}
