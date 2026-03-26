#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blockchain/pkcertchain.h"
#include "Proofs/MiniPoW/miniPoWResult.h"
#include "Proofs/powManager.h"

int main() {
    printf("--- End-to-End PowManager Integration Test ---\n");

    PKCertChain chain;
    memset(&chain, 0, sizeof(chain));
    strcpy(chain.NetworkName, "local_testnet");
    
    // Gensis_Block sets complexities to 100, indices to 0
    if (Gensis_Block(&chain) != OP_SUCCESS) {
        printf("Genesis Block creation failed.\n");
        return 1;
    }
    printf("Genesis block created. Initial Complexities: MCU=%u, SERVER=%u\n", chain.MCUComplexity, chain.ServerComplexity);

    // Stub MiniPowResult
    MiniPowResult miniResult;
    minipowresult_init(&miniResult);
    miniResult.challengeid = 1234;
    miniResult.sessionid = 5678;
    miniResult.isValid = true;
    
    Tier_t tiers[] = {TIER_MCU, TIER_SERVER, TIER_DESKTOP, TIER_EDGE};
    const char *tierNames[] = {"MCU", "SERVER", "DESKTOP", "EDGE"};

    for (int i = 0; i < 4; i++) {
        miniResult.tier = tiers[i];
        printf("\n--- Processing Tier: %s ---\n", tierNames[i]);
        
        OpStatus_t st = PKCertChain_AddBlockWithPoW(&chain, &miniResult, tiers[i]);
        if (st != OP_SUCCESS) {
            printf("Failed to add block for tier %s. Code: %d\n", tierNames[i], st);
            return 1;
        }

        block *newBlock = &chain.blocks[chain.index - 1];
        printf("Block added! Height: %lu\n", newBlock->height);
        printf("MiniPoWResult isValid: %s, session: %u\n", newBlock->miniPowResult.isValid ? "true" : "false", newBlock->miniPowResult.sessionid);
        printf("TierPoWResult challenge_id: %lu, complexity: %u, nonce: %lu\n", 
               newBlock->tierPoWResult.challenge_id, 
               newBlock->tierPoWResult.complexity,
               newBlock->tierPoWResult.nonce);
        
        uint32_t lastIndex = 0;
        uint8_t newComplexity = 0;
        switch(tiers[i]) {
            case TIER_MCU: lastIndex = chain.lastMCUBlockIndex; newComplexity = chain.MCUComplexity; break;
            case TIER_SERVER: lastIndex = chain.lastServerBlockIndex; newComplexity = chain.ServerComplexity; break;
            case TIER_DESKTOP: lastIndex = chain.lastDesktopBlockIndex; newComplexity = chain.DesktopComplexity; break;
            case TIER_EDGE: lastIndex = chain.lastEdgeBlockIndex; newComplexity = chain.EdgeComplexity; break;
            default: break;
        }
        printf("Updated Chain State for %s - LastIndex: %u, New Complexity: %u\n", tierNames[i], lastIndex, newComplexity);
    }
    
    printf("\nAll End-to-End steps completed successfully.\n");
    return 0;
}
