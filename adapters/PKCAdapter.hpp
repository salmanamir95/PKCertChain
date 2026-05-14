#pragma once

#include <cstdint>
#include <string>
#include <tuple>

#include "adapter/IAdapter.h"
#include "runtime/taskhandle.h"
#include "core/types/input.h"
#include "core/types/noinput.h"

#include "protocol/blockchain/PKCertChain.h"
#include "protocol/blockchain/block.h"
#include "protocol/blockchain/certificate.h"

class PKCAdapter : public IAdapter {
private:
    PKCertChain* chain = nullptr;

public:
    // =================================================
    // BINDING
    // =================================================
    void bindChain(PKCertChain* c);

    // =================================================
    // IAdapter LIFECYCLE
    // =================================================
    void init() override;
    void tick() override;

    // =================================================
    // ASYNC GETTERS
    // =================================================
    TaskHandle getIndex();
    TaskHandle getNetworkName();
    TaskHandle getComplexity();
    TaskHandle getNextChallengeId();
    TaskHandle getAvgSolveTime();

    // =================================================
    // BLOCK OPS
    // =================================================
    TaskHandle getBlock(uint32_t index);
    TaskHandle addBlock(const block& blk);

    // =================================================
    // SETTERS
    // =================================================
    TaskHandle setNetworkName(const std::string& name);
    TaskHandle setComplexity(uint8_t c);
    TaskHandle setNextChallengeId(uint64_t id);
    TaskHandle setAvgSolveTime(double t);

    // =================================================
    // STATE OPS
    // =================================================
    TaskHandle updateLastIndexes(uint32_t mcu,
                                 uint32_t server,
                                 uint32_t desktop,
                                 uint32_t edge);

    // =================================================
    // CERTIFICATE OPS
    // =================================================
    TaskHandle createCertificate(uint256 signPub,
                                 uint256 encPub,
                                 ipv6_t id);
};