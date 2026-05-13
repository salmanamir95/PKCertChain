#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "system/utilities.h"
#include "Proofs/MiniPoW/miniPoWManager_ops.h"
#include "protocol/proofs/mini_pow/mini_pow_Solve_t.h"

int main(void)
{
    printf("Starting PKCertChain Node...\n");
    printf("Evaluating Node Hardware Capability Tier (MiniPoW)...\n");

    // Initialize Manager Tracker
    MiniPoWManagerTracker manager;
    uint32_t sessionID = 1;
    minipow_manager_tracker_init(&manager, sessionID);

    // Live matrices generation
    mini_pow_Matrix *matrices = calloc(1, sizeof(mini_pow_Matrix));
    if (!matrices) {
        printf("Memory allocation failed for matrices.\n");
        return 1;
    }

    certificate dummy_cert;
    memset(&dummy_cert, 0, sizeof(dummy_cert));
    uint256 dummy_hash;
    memset(&dummy_hash, 0, sizeof(dummy_hash));

    if (construct_mini_pow_matrices(&dummy_cert, &dummy_hash, sessionID, 1000, matrices) != OP_SUCCESS) {
        printf("Failed to generate matrices securely.\n");
        free(matrices);
        return 1;
    }

    // Prepare solve context
    mini_pow_solve_t receiverSolve; 
    mini_pow_solve_init(&receiverSolve);
    SolvedMatricPoW *solvedMatrix = calloc(1, sizeof(SolvedMatricPoW));
    if (!solvedMatrix) {
        printf("Memory allocation failed for solved matrix.\n");
        free(matrices);
        return 1;
    }

    printf("Executing Challenge Matrix loops...\n");
    
    // Process Iterations iteratively
    for (uint32_t i = 0; i < MINI_POW_MATRIX_N; ++i) {
        uint32_t currentChallengeID = 1000 + i;
        
        // --- SENDER (Manager) ---
        mini_pow_challenge_t challenge;
        mini_pow_challenge_init(&challenge);
        challenge.challenge_id = currentChallengeID;
        challenge.session_id = sessionID;
        challenge.iteration = i;
        
        // Populate the respective column and row correctly
        for(size_t k = 0; k < MINI_POW_MATRIX_N; ++k) {
            challenge.columnOfA[k] = matrices->A[k][i]; // i-th column
            challenge.rowOfB[k] = matrices->B[i][k];    // i-th row
        }
        
        minipow_manager_send(&manager, currentChallengeID);
        
        // --- RECEIVER (Miner) ---
        mini_pow_solve_update(&receiverSolve, &challenge);
        
        minipow_manager_receive_ack(&manager);
    }

    // Finalize metric
    solved_matric_pow_init(solvedMatrix);
    solvedMatrix->session_id = sessionID;
    solvedMatrix->challenge_id = 1000 + MINI_POW_MATRIX_N - 1;
    memcpy(solvedMatrix->Matrix, receiverSolve.resultMatrix, sizeof(solvedMatrix->Matrix));

    // Evaluate
    mini_pow_result result = minipow_manager_finalize(&manager, solvedMatrix, matrices);
    
    printf("\n========================================\n");
    printf("PKCertChain Node Startup Configuration\n");
    printf("Session ID: %u\n", result.sessionid);
    printf("Final Challenge ID: %u\n", result.challengeid);
    printf("Hardware Tier Assigned: %d\n", result.tier);
    printf("Matrix Integrity Valid: %s\n", result.isValid ? "True" : "False");
    printf("========================================\n\n");
    
    free(solvedMatrix);
    free(matrices);

    if (!result.isValid) {
        printf("FATAL: MiniPoW Node Evaluation Failed. Exiting.\n");
        return 1;
    }

    printf("Node initialized successfully. Listening for connections...\n");
    // Event loop would boot up fully here...

    return 0;
}
