#include "PKCAdapter.h"
#include "runtime/tasksystem.h"

// =================================================
// BINDING
// =================================================

void BlockchainAdapter::bindChain(PKCertChain* c)
{
    chain = c;
}

// =================================================
// LIFECYCLE (IAdapter)
// =================================================

void BlockchainAdapter::init()
{
    if (!chain) return;

    // optional: initialize genesis automatically if needed
    if (chain->index == 0) {
        Gensis_Block(chain);
    }
}

void BlockchainAdapter::tick()
{
    // telemetry only (future metrics, chain health, etc.)
}

// =================================================
// GETTERS
// =================================================

TaskHandle BlockchainAdapter::getIndex()
{
    return taskSystem->submit(
        Input<NoInput>{},
        [this](Input<NoInput>) {
            return chain->index;
        }
    );
}

TaskHandle BlockchainAdapter::getNetworkName()
{
    return taskSystem->submit(
        Input<NoInput>{},
        [this](Input<NoInput>) {
            return std::string(chain->NetworkName);
        }
    );
}

TaskHandle BlockchainAdapter::getComplexity()
{
    return taskSystem->submit(
        Input<NoInput>{},
        [this](Input<NoInput>) {
            return chain->complexity;
        }
    );
}

TaskHandle BlockchainAdapter::getNextChallengeId()
{
    return taskSystem->submit(
        Input<NoInput>{},
        [this](Input<NoInput>) {
            return chain->next_challenge_id;
        }
    );
}

TaskHandle BlockchainAdapter::getAvgSolveTime()
{
    return taskSystem->submit(
        Input<NoInput>{},
        [this](Input<NoInput>) {
            return chain->avg_solve_time_seconds;
        }
    );
}

// =================================================
// BLOCK OPS
// =================================================

TaskHandle BlockchainAdapter::getBlock(uint32_t index)
{
    return taskSystem->submit(
        Input<uint32_t>{index},
        [this](Input<uint32_t> in) -> std::any {

            uint32_t i = in.get();
            if (i >= chain->index)
                return false;

            return chain->blocks[i];
        }
    );
}

TaskHandle BlockchainAdapter::addBlock(const block& blk)
{
    return taskSystem->submit(
        Input<block>{blk},
        [this](Input<block> in) -> std::any {

            if (chain->index >= 100)
                return false;

            chain->blocks[chain->index++] = in.get();
            return true;
        }
    );
}

// =================================================
// SETTERS
// =================================================

TaskHandle BlockchainAdapter::setNetworkName(const std::string& name)
{
    return taskSystem->submit(
        Input<std::string>{name},
        [this](Input<std::string> in) {

            const auto& n = in.get();
            strncpy(chain->NetworkName, n.c_str(), sizeof(chain->NetworkName) - 1);
            chain->NetworkName[63] = '\0';
        }
    );
}

TaskHandle BlockchainAdapter::setComplexity(uint8_t c)
{
    return taskSystem->submit(
        Input<uint8_t>{c},
        [this](Input<uint8_t> in) {
            chain->complexity = in.get();
        }
    );
}

TaskHandle BlockchainAdapter::setNextChallengeId(uint64_t id)
{
    return taskSystem->submit(
        Input<uint64_t>{id},
        [this](Input<uint64_t> in) {
            chain->next_challenge_id = in.get();
        }
    );
}

TaskHandle BlockchainAdapter::setAvgSolveTime(double t)
{
    return taskSystem->submit(
        Input<double>{t},
        [this](Input<double> in) {
            chain->avg_solve_time_seconds = in.get();
        }
    );
}

// =================================================
// STATE OPS
// =================================================

TaskHandle BlockchainAdapter::updateLastIndexes(uint32_t mcu,
                                               uint32_t server,
                                               uint32_t desktop,
                                               uint32_t edge)
{
    return taskSystem->submit(
        Input<std::tuple<uint32_t,uint32_t,uint32_t,uint32_t>>{
            std::make_tuple(mcu, server, desktop, edge)
        },
        [this](Input<std::tuple<uint32_t,uint32_t,uint32_t,uint32_t>> in) {

            auto [m, s, d, e] = in.get();

            chain->lastMCUBlockIndex = m;
            chain->lastServerBlockIndex = s;
            chain->lastDesktopBlockIndex = d;
            chain->lastEdgeBlockIndex = e;
        }
    );
}

// =================================================
// CERTIFICATE OPS
// =================================================

TaskHandle BlockchainAdapter::createCertificate(uint256 signPub,
                                               uint256 encPub,
                                               ipv6_t id)
{
    return taskSystem->submit(
        Input<std::tuple<uint256,uint256,ipv6_t>>{
            std::make_tuple(signPub, encPub, id)
        },
        [](Input<std::tuple<uint256,uint256,ipv6_t>> in) -> std::any {

            auto [sign, enc, nid] = in.get();

            certificate cert;
            cert_init(&cert);

            cert_set_pubSignKey(&cert, &sign);
            cert_set_pubEncKey(&cert, &enc);
            cert_set_id(&cert, &nid);

            return cert;
        }
    );
}