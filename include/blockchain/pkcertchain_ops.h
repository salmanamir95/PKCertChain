#ifndef PKCERTCHAIN_H
#define PKCERTCHAIN_H





#ifndef PKCERTCHAIN_INLINE
#define PKCERTCHAIN_INLINE static inline __attribute__((always_inline))
#endif

#include <math.h>
#include <stdint.h>
#include <string.h>
#include "blockchain/block.h"

typedef struct __attribute__((aligned(4))) {
    block blocks[100]; //148
    uint32_t index;
    char NetworkName[64];
    uint8_t complexity;
    uint64_t next_challenge_id;
    double avg_solve_time_seconds;
    uint32_t lastMCUBlockIndex;
    uint32_t lastServerBlockIndex;
    uint32_t lastDesktopBlockIndex;
    uint32_t lastEdgeBlockIndex;

    uint8_t MCUComplexity;
    uint8_t ServerComplexity;
    uint8_t DesktopComplexity;
    uint8_t EdgeComplexity;
} PKCertChain;

#include "crypto/SignUtils.h"
#include "crypto/EncUtils.h"
#include "protocol/proofs/mini_pow/mini_pow_challenge_t.h"
#include "protocol/proofs/mini_pow/mini_pow_Solve_t.h"
#include "protocol/proofs/mini_pow/mini_pow_Verify_t.h"
#include "protocol/proofs/mini_pow/mini_pow_Session_t.h"
#include "protocol/proofs/mini_pow/mini_pow_Queue_t.h"
#include "protocol/proofs/mini_pow/mini_pow_Classify_t.h"
#include "Proofs/TierPoW/tierPoWChallenge.h"
#include "Proofs/TierPoW/tierPoWSolve.h"
#include "Proofs/TierPoW/tierPoWVerify.h"
#include "Proofs/TierPoW/tierPoWSession.h"
#include "Proofs/TierPoW/tierPoWQueue.h"

PKCERTCHAIN_INLINE OpStatus_t Gensis_Block(PKCertChain *chain)
{
    if (!chain) return OP_NULL_PTR;
    if (chain->index != 0) return OP_INVALID_STATE;

    block *genesis = &chain->blocks[0];
    block_init(genesis);

    uint256 sign_priv;
    uint256 sign_pub;
    uint256 enc_priv;
    uint256 enc_pub;

    if (GenerateSignKeys(&sign_priv, &sign_pub, chain->NetworkName) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (GenerateEncKeys(&enc_priv, &enc_pub, chain->NetworkName) != OP_SUCCESS) return OP_INVALID_INPUT;

    certificate cert;
    cert_init(&cert);
    cert_set_pubSignKey(&cert, &sign_pub);
    cert_set_pubEncKey(&cert, &enc_pub);
    cert_set_id(&cert, 1);

    uint512 sig;
    if (cert_sign(&cert, &sign_priv, &sig) != OP_SUCCESS) return OP_INVALID_INPUT;

    block_set_cert(genesis, &cert);
    block_set_signed_by_verifier(genesis, &sig);
    block_set_height(genesis, 0);
    block_set_timestamp(genesis, 0);

    uint256 cert_hash;
    if (hash_certificate(&cert, &cert_hash) != OP_SUCCESS) return OP_INVALID_INPUT;
    block_set_current_cert_hash(genesis, &cert_hash);

    // Genesis has no previous block
    uint256_zero(&genesis->prevHash);

    chain->index = 1;
    chain->complexity = 1;
    memset(chain->NetworkName, 0, sizeof(chain->NetworkName));
    chain->next_challenge_id = 1;
    chain->avg_solve_time_seconds = 600.0;
    
    chain->lastMCUBlockIndex = 0;
    chain->lastServerBlockIndex = 0;
    chain->lastDesktopBlockIndex = 0;
    chain->lastEdgeBlockIndex = 0;

    chain->MCUComplexity = 10;
    chain->ServerComplexity = 20;
    chain->DesktopComplexity = 30;
    chain->EdgeComplexity = 40;
    return OP_SUCCESS;
}



#include "system/LinuxUtils.h"

PKCERTCHAIN_INLINE OpStatus_t save_chain_state(const char *network_name, const PKCertChain *chain)
{
    if (!network_name || network_name[0] == '\0' || !chain) return OP_INVALID_INPUT;

    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') return OP_INVALID_INPUT;

    OpStatus_t st = ensure_wallet_dir(network_name);
    if (st != OP_SUCCESS) return st;

    char state_path[512];
    if (snprintf(state_path, sizeof(state_path), "%s/%s/%s/%s",
                 home, PKCERTCHAIN_BASE_SUBDIR, network_name, PKCERTCHAIN_CHAIN_STATE_FILE) <= 0)
        return OP_INVALID_INPUT;

    const uint32_t index = chain->index;
    if (index > 100) return OP_INVALID_INPUT;

    const size_t header_len = PKCERTCHAIN_CHAIN_MAGIC_LEN + 1 + 64 + 1 + UINT64_SIZE + UINT32_SIZE;
    const size_t blocks_len = (size_t)index * BLOCK_SIZE;
    const size_t payload_len = header_len + blocks_len;
    const size_t total_len = payload_len + UINT256_SIZE; // append hash

    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) return OP_INVALID_INPUT;

    size_t off = 0;
    memcpy(buf + off, PKCERTCHAIN_CHAIN_MAGIC, PKCERTCHAIN_CHAIN_MAGIC_LEN);
    off += PKCERTCHAIN_CHAIN_MAGIC_LEN;
    serialize_u8(PKCERTCHAIN_CHAIN_VERSION, buf + off);
    off += 1;
    memcpy(buf + off, chain->NetworkName, 64);
    off += 64;
    serialize_u8(chain->complexity, buf + off);
    off += 1;
    serialize_u64_be(chain->next_challenge_id, buf + off);
    off += UINT64_SIZE;
    serialize_u32_be(index, buf + off);
    off += UINT32_SIZE;

    for (uint32_t i = 0; i < index; ++i) {
        if (block_serialize(&chain->blocks[i], buf + off, BLOCK_SIZE) != OP_SUCCESS) {
            free(buf);
            return OP_INVALID_INPUT;
        }
        off += BLOCK_SIZE;
    }

    if (off != payload_len) {
        free(buf);
        return OP_INVALID_INPUT;
    }

    uint256 hash;
    hash256_buffer(buf, payload_len, &hash);
    if (uint256_serialize_be(&hash, buf + payload_len, UINT256_SIZE) != OP_SUCCESS) {
        free(buf);
        return OP_INVALID_INPUT;
    }

    st = save_file_0600(state_path, buf, total_len);
    free(buf);
    return st;
}

PKCERTCHAIN_INLINE OpStatus_t load_chain_state(const char *network_name, PKCertChain *out_chain)
{
    if (!network_name || network_name[0] == '\0' || !out_chain) return OP_INVALID_INPUT;

    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') return OP_INVALID_INPUT;

    char state_path[512];
    if (snprintf(state_path, sizeof(state_path), "%s/%s/%s/%s",
                 home, PKCERTCHAIN_BASE_SUBDIR, network_name, PKCERTCHAIN_CHAIN_STATE_FILE) <= 0)
        return OP_INVALID_INPUT;

    uint8_t *buf = NULL;
    size_t len = 0;
    int err = 0;
    OpStatus_t st = read_file_alloc(state_path, &buf, &len, &err);
    if (st != OP_SUCCESS) return st;

    const size_t header_len = PKCERTCHAIN_CHAIN_MAGIC_LEN + 1 + 64 + 1 + UINT64_SIZE + UINT32_SIZE;
    if (len < header_len + UINT256_SIZE) {
        free(buf);
        return OP_INVALID_INPUT;
    }

    const size_t payload_len = len - UINT256_SIZE;
    const uint8_t *stored_hash = buf + payload_len;

    uint256 calc_hash;
    hash256_buffer(buf, payload_len, &calc_hash);
    uint8_t calc_hash_buf[UINT256_SIZE];
    if (uint256_serialize_be(&calc_hash, calc_hash_buf, sizeof(calc_hash_buf)) != OP_SUCCESS) {
        free(buf);
        return OP_INVALID_INPUT;
    }
    if (memcmp(calc_hash_buf, stored_hash, UINT256_SIZE) != 0) {
        free(buf);
        return OP_INVALID_INPUT;
    }

    size_t off = 0;
    if (memcmp(buf + off, PKCERTCHAIN_CHAIN_MAGIC, PKCERTCHAIN_CHAIN_MAGIC_LEN) != 0) {
        free(buf);
        return OP_INVALID_INPUT;
    }
    off += PKCERTCHAIN_CHAIN_MAGIC_LEN;

    if (buf[off] != PKCERTCHAIN_CHAIN_VERSION) {
        free(buf);
        return OP_INVALID_INPUT;
    }
    off += 1;

    memset(out_chain, 0, sizeof(*out_chain));
    memcpy(out_chain->NetworkName, buf + off, 64);
    off += 64;

    out_chain->complexity = buf[off];
    off += 1;

    deserialize_u64_be(buf + off, &out_chain->next_challenge_id, sizeof(uint64_t));
    off += UINT64_SIZE;

    uint32_t index = 0;
    deserialize_u32_be(buf + off, &index, sizeof(uint32_t));
    off += UINT32_SIZE;

    if (index > 100) {
        free(buf);
        return OP_INVALID_INPUT;
    }

    const size_t expected_len = header_len + ((size_t)index * BLOCK_SIZE);
    if (payload_len != expected_len) {
        free(buf);
        return OP_INVALID_INPUT;
    }

    out_chain->index = index;
    for (uint32_t i = 0; i < index; ++i) {
        if (block_deserialize(buf + off, BLOCK_SIZE, &out_chain->blocks[i]) != OP_SUCCESS) {
            free(buf);
            return OP_INVALID_INPUT;
        }
        off += BLOCK_SIZE;
    }

    free(buf);
    return OP_SUCCESS;
}
#endif // PKCERTCHAIN_H
