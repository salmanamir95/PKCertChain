#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Proofs/MiniPoW/miniPoWManager.h"
#include "Proofs/MiniPoW/miniPoWChallengeSendQueue.h"
#include "Proofs/MiniPoW/miniPoWChallengeReceiveQueue.h"
#include "Proofs/MiniPoW/miniPoWSolve.h"
#include "Proofs/MiniPoW/miniPoWVerify.h"
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
    
    // Mock matrices for testing
    mini_pow_Matrix *matrices = calloc(1, sizeof(mini_pow_Matrix));
    for(size_t r = 0; r < MINI_POW_MATRIX_N; ++r) {
        for(size_t c = 0; c < MINI_POW_MATRIX_N; ++c) {
            matrices->A[r][c] = (uint16_t)((r + c) % 100);
            matrices->B[r][c] = (uint16_t)((r * c) % 100);
        }
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
                
                bool isValid = mini_pow_verify(solvedMatrix, matrices);
                printf("\nFinal Verification result: %s\n", isValid ? "CORRECT" : "INCORRECT");
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
