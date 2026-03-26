#ifndef TIER_POW_RESULT_H
#define TIER_POW_RESULT_H

#include "pkcertchain_config.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "blockchain/Tier.h"
#include "Proofs/TierPoW/tierPoWChallenge.h"
#include "Proofs/TierPoW/tierPoWSolve.h"
#include "util/To_BO_BE_Pimitives.h"
#include "util/To_BO_Def_Primitives.h"
#include "datatype/OpStatus.h"

// Total serialized size: 1 + 3 + 44 + 20 + 8 = 76 bytes
typedef struct __attribute__((aligned(4))) {
    Tier_t tier;                      
    uint8_t reserved[3];              
    tier_pow_challenge_t challenge;   
    tier_pow_solve_t solve;           
    double time_taken;                
} TierPowResult;

#define TIER_POW_RESULT_SERIALIZED_SIZE (1 + 3 + 44 + 20 + 8) 

static inline void tierpowresult_init(TierPowResult *res) {
    if (!res) return;
    res->tier = TIER_INVALID;
    memset(res->reserved, 0, 3);
    memset(&res->challenge, 0, sizeof(res->challenge));
    tier_pow_solve_init(&res->solve);
    res->time_taken = 0.0;
}

static inline OpStatus_t tierpowresult_serialize(const TierPowResult *res, uint8_t *out, size_t out_size) {
    if (!res || !out) return OP_NULL_PTR;
    if (out_size < TIER_POW_RESULT_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    size_t off = 0;
    out[off++] = res->tier;
    out[off++] = res->reserved[0];
    out[off++] = res->reserved[1];
    out[off++] = res->reserved[2];

    uint256_serialize_be(&res->challenge.challenge, out + off, UINT256_SIZE);
    off += UINT256_SIZE;
    out[off++] = res->challenge.complexity;
    serialize_u64_be(res->challenge.challenge_id, out + off);
    off += 8;
    out[off++] = res->challenge.reserved[0];
    out[off++] = res->challenge.reserved[1];
    out[off++] = res->challenge.reserved[2];

    serialize_u64_be(res->solve.nonce, out + off);
    off += 8;
    out[off++] = res->solve.complexity;
    serialize_u64_be(res->solve.challenge_id, out + off);
    off += 8;
    out[off++] = res->solve.reserved[0];
    out[off++] = res->solve.reserved[1];
    out[off++] = res->solve.reserved[2];

    uint64_t time_bits;
    memcpy(&time_bits, &res->time_taken, 8);
    serialize_u64_be(time_bits, out + off);
    off += 8;

    return OP_SUCCESS;
}

static inline OpStatus_t tierpowresult_deserialize(const uint8_t *in, size_t in_size, TierPowResult *res) {
    if (!res || !in) return OP_NULL_PTR;
    if (in_size < TIER_POW_RESULT_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    size_t off = 0;
    res->tier = (Tier_t)in[off++];
    res->reserved[0] = in[off++];
    res->reserved[1] = in[off++];
    res->reserved[2] = in[off++];

    uint256_deserialize_be(in + off, UINT256_SIZE, &res->challenge.challenge);
    off += UINT256_SIZE;
    res->challenge.complexity = in[off++];
    deserialize_u64_be(in + off, &res->challenge.challenge_id, 8);
    off += 8;
    res->challenge.reserved[0] = in[off++];
    res->challenge.reserved[1] = in[off++];
    res->challenge.reserved[2] = in[off++];

    deserialize_u64_be(in + off, &res->solve.nonce, 8);
    off += 8;
    res->solve.complexity = in[off++];
    deserialize_u64_be(in + off, &res->solve.challenge_id, 8);
    off += 8;
    res->solve.reserved[0] = in[off++];
    res->solve.reserved[1] = in[off++];
    res->solve.reserved[2] = in[off++];

    uint64_t time_bits;
    deserialize_u64_be(in + off, &time_bits, 8);
    memcpy(&res->time_taken, &time_bits, 8);
    off += 8;

    return OP_SUCCESS;
}

#endif // TIER_POW_RESULT_H
