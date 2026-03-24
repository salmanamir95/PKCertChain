#ifndef MINI_POW_CHALLENGE_H
#define MINI_POW_CHALLENGE_H

#include "pkcertchain_config.h"

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "datatype/OpStatus.h"
#include "blockchain/block.h"
#include "datatype/uint256_t.h"
#include "util/SignUtils.h"
#include "util/To_BO_BE_Pimitives.h"
#include "util/To_BO_Def_Primitives.h"
#include "util/Size_Offsets.h"
#include "Proofs/MiniPoW/miniPoWClassify.h"

#define MINI_POW_CHALLENGE_INLINE static inline __attribute__((always_inline))

#define MINI_POW_CHALLENGE_SERIALIZED_SIZE MINI_POW_CHALLENGE_SIZE

/*
 * mini_pow_challenge_t:
 *  - 4-byte aligned (32-bit alignment)
 *  - deterministic seed for matrix generation
 *  - row/col selection for streamed computation
 */
typedef struct __attribute__((aligned(4))) {
    uint256 seed;            // 32 bytes
    uint16_t matrix_n;       // 2 bytes (expected 1000)
    uint16_t row;            // 2 bytes
    uint16_t col;            // 2 bytes
    uint16_t iteration;      // 2 bytes
    uint16_t total_iterations; // 2 bytes
    uint64_t challenge_id;   // 8 bytes
    uint8_t reserved[2];     // padding to 4-byte multiple
} mini_pow_challenge_t;

MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_init(mini_pow_challenge_t * pow){
    uint256_zero(&pow->seed);
    pow->matrix_n = MINI_POW_MATRIX_N;
    pow->row = 0;
    pow->col = 0;
    pow->iteration = 0;
    pow->total_iterations = MINI_POW_MATRIX_N;
    pow->challenge_id = 0;
    memset(pow->reserved, 0, sizeof(pow->reserved));
}

MINI_POW_CHALLENGE_INLINE const uint256* mini_pow_challenge_get_challenge(const mini_pow_challenge_t * pow){
    return &pow->seed;
}

MINI_POW_CHALLENGE_INLINE const uint64_t* mini_pow_challenge_get_challenge_id(const mini_pow_challenge_t * pow){
    return &pow->challenge_id;
}

MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_set_challenge(mini_pow_challenge_t * pow, const uint256 * seed){
    uint256_copy(&pow->seed, seed);
}

MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_set_challenge_id(mini_pow_challenge_t * pow, uint64_t id){
    pow->challenge_id = id;
}

MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_copy(mini_pow_challenge_t * dst, const mini_pow_challenge_t * src){
    uint256_copy(&dst->seed, &src->seed);
    dst->matrix_n = src->matrix_n;
    dst->row = src->row;
    dst->col = src->col;
    dst->iteration = src->iteration;
    dst->total_iterations = src->total_iterations;
    dst->challenge_id = src->challenge_id;
    memset(dst->reserved, 0, sizeof(dst->reserved));
}

MINI_POW_CHALLENGE_INLINE OpStatus_t mini_pow_challenge_serialize(const mini_pow_challenge_t *pow, uint8_t *out, size_t out_size)
{
    if (!pow || !out) return OP_NULL_PTR;
    if (out_size < MINI_POW_CHALLENGE_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    if (uint256_serialize_be(&pow->seed, out, UINT256_SIZE) != OP_SUCCESS) return OP_INVALID_INPUT;
    serialize_u16_be(pow->matrix_n, out + UINT256_SIZE);
    serialize_u16_be(pow->row, out + UINT256_SIZE + UINT16_SIZE);
    serialize_u16_be(pow->col, out + UINT256_SIZE + 2 * UINT16_SIZE);
    serialize_u16_be(pow->iteration, out + UINT256_SIZE + 3 * UINT16_SIZE);
    serialize_u16_be(pow->total_iterations, out + UINT256_SIZE + 4 * UINT16_SIZE);
    serialize_u64_be(pow->challenge_id, out + UINT256_SIZE + 5 * UINT16_SIZE);
    memcpy(out + UINT256_SIZE + 5 * UINT16_SIZE + UINT64_SIZE, pow->reserved, sizeof(pow->reserved));
    return OP_SUCCESS;
}

MINI_POW_CHALLENGE_INLINE OpStatus_t mini_pow_challenge_deserialize(const uint8_t *in, size_t in_size, mini_pow_challenge_t *pow)
{
    if (!pow || !in) return OP_NULL_PTR;
    if (in_size < MINI_POW_CHALLENGE_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    if (uint256_deserialize_be(in, UINT256_SIZE, &pow->seed) != OP_SUCCESS) return OP_INVALID_INPUT;
    deserialize_u16_be(in + UINT256_SIZE, &pow->matrix_n, sizeof(uint16_t));
    deserialize_u16_be(in + UINT256_SIZE + UINT16_SIZE, &pow->row, sizeof(uint16_t));
    deserialize_u16_be(in + UINT256_SIZE + 2 * UINT16_SIZE, &pow->col, sizeof(uint16_t));
    deserialize_u16_be(in + UINT256_SIZE + 3 * UINT16_SIZE, &pow->iteration, sizeof(uint16_t));
    deserialize_u16_be(in + UINT256_SIZE + 4 * UINT16_SIZE, &pow->total_iterations, sizeof(uint16_t));
    deserialize_u64_be(in + UINT256_SIZE + 5 * UINT16_SIZE, &pow->challenge_id, sizeof(uint64_t));
    memcpy(pow->reserved, in + UINT256_SIZE + 5 * UINT16_SIZE + UINT64_SIZE, sizeof(pow->reserved));
    return OP_SUCCESS;
}

/*
 * generate_mini_pow_Challenge:
 *  - Computes SHA256 hash over the block struct to derive seed
 *  - Returns mini_pow_challenge_t with row/col and iteration metadata
 */
MINI_POW_CHALLENGE_INLINE OpStatus_t generate_mini_pow_Challenge(block* block,
                                                                 uint16_t row,
                                                                 uint16_t col,
                                                                 uint16_t iteration,
                                                                 uint16_t total_iterations,
                                                                 uint64_t challenge_id,
                                                                 mini_pow_challenge_t* pow)
{
    uint8_t buf[CERT_SIZE + UINT256_SIZE + UINT64_SIZE + UINT64_SIZE];
    const size_t packed_len = sizeof(buf);

    if (!block || !pow) return OP_NULL_PTR;

    uint256_serialize_be(&block->cert.pubSignKey, buf, UINT256_SIZE);
    uint256_serialize_be(&block->cert.pubEncKey, buf + UINT256_SIZE, UINT256_SIZE);
    buf[CERT_SIZE - 1] = block->cert.id;

    uint256_serialize_be(&block->prevHash, buf + CERT_SIZE, UINT256_SIZE);
    serialize_u64_be(block->height, buf + CERT_SIZE + UINT256_SIZE);
    serialize_u64_be(block->timestamp, buf + CERT_SIZE + UINT256_SIZE + UINT64_SIZE);

    hash256_buffer(buf, packed_len, &pow->seed);

    pow->matrix_n = MINI_POW_MATRIX_N;
    pow->row = row;
    pow->col = col;
    pow->iteration = iteration;
    pow->total_iterations = total_iterations;
    pow->challenge_id = challenge_id;

    return OP_SUCCESS;
}
#endif // MINI_POW_CHALLENGE_H
