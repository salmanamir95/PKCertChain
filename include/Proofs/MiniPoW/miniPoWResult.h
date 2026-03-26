#ifndef MINI_POW_RESULT_H
#define MINI_POW_RESULT_H

#include <stdint.h>
#include <stdbool.h>
#include "Proofs/MiniPoW/solvedMatricPoW.h"
#include "Proofs/MiniPoW/miniPoWMatrix.h"
#include "blockchain/Tier.h"

// The final result returned by the manager
typedef struct {
    uint32_t challengeid;
    uint32_t sessionid;
    const mini_pow_Matrix *minipowmatrix;
    const SolvedMatricPoW *solvedmatrix;
    Tier_t tier;
    bool isValid;
} mini_pow_result;

#define MINI_POW_RESULT_SERIALIZED_SIZE 12

typedef struct __attribute__((aligned(4))) {
    uint32_t challengeid; // 4
    uint32_t sessionid;   // 4
    Tier_t tier;          // 1
    bool isValid;         // 1
    uint8_t reserved[2];  // 2 -> Total 12
} MiniPowResult;

static inline __attribute__((always_inline)) void minipowresult_init(MiniPowResult *res) {
    res->challengeid = 0;
    res->sessionid = 0;
    res->tier = TIER_INVALID;
    res->isValid = false;
    res->reserved[0] = 0; res->reserved[1] = 0;
}

static inline __attribute__((always_inline)) OpStatus_t minipowresult_serialize(const MiniPowResult *res, uint8_t *out, size_t out_size) {
    if (!res || !out) return OP_NULL_PTR;
    if (out_size < MINI_POW_RESULT_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;
    out[0] = (res->challengeid >> 24) & 0xFF;
    out[1] = (res->challengeid >> 16) & 0xFF;
    out[2] = (res->challengeid >> 8) & 0xFF;
    out[3] = res->challengeid & 0xFF;
    out[4] = (res->sessionid >> 24) & 0xFF;
    out[5] = (res->sessionid >> 16) & 0xFF;
    out[6] = (res->sessionid >> 8) & 0xFF;
    out[7] = res->sessionid & 0xFF;
    out[8] = res->tier;
    out[9] = res->isValid ? 1 : 0;
    out[10] = res->reserved[0];
    out[11] = res->reserved[1];
    return OP_SUCCESS;
}

static inline __attribute__((always_inline)) OpStatus_t minipowresult_deserialize(const uint8_t *in, size_t in_size, MiniPowResult *res) {
    if (!res || !in) return OP_NULL_PTR;
    if (in_size < MINI_POW_RESULT_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;
    res->challengeid = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
    res->sessionid = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | in[7];
    res->tier = (Tier_t)in[8];
    res->isValid = in[9] != 0;
    res->reserved[0] = in[10];
    res->reserved[1] = in[11];
    return OP_SUCCESS;
}

#endif // MINI_POW_RESULT_H
