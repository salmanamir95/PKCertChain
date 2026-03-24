#ifndef MINI_POW_CHALLENGE_H
#define MINI_POW_CHALLENGE_H

#include "pkcertchain_config.h"

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "datatype/OpStatus.h"
#include "util/To_BO_BE_Pimitives.h"
#include "util/To_BO_Def_Primitives.h"
#include "util/Size_Offsets.h"
#include "Proofs/MiniPoW/miniPoWClassify.h"

#define MINI_POW_CHALLENGE_INLINE static inline __attribute__((always_inline))

#define MINI_POW_CHALLENGE_SERIALIZED_SIZE MINI_POW_CHALLENGE_SIZE

/*
 * mini_pow_challenge_t:
 *  - minimal fields sent to miner
 *  - matrix_n is implicit (MINI_POW_MATRIX_N)
 */
typedef struct __attribute__((aligned(4))) {
    uint64_t challenge_id;   // 8 bytes
    uint16_t row;            // 2 bytes
    uint16_t col;            // 2 bytes
    uint16_t iteration;      // 2 bytes (0..999)
} mini_pow_challenge_t;

MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_init(mini_pow_challenge_t *pow)
{
    pow->challenge_id = 0;
    pow->row = 0;
    pow->col = 0;
    pow->iteration = 0;
}

MINI_POW_CHALLENGE_INLINE const uint64_t* mini_pow_challenge_get_challenge_id(const mini_pow_challenge_t *pow)
{
    return &pow->challenge_id;
}

MINI_POW_CHALLENGE_INLINE void mini_pow_challenge_copy(mini_pow_challenge_t *dst, const mini_pow_challenge_t *src)
{
    dst->challenge_id = src->challenge_id;
    dst->row = src->row;
    dst->col = src->col;
    dst->iteration = src->iteration;
}

MINI_POW_CHALLENGE_INLINE OpStatus_t mini_pow_challenge_serialize(const mini_pow_challenge_t *pow,
                                                                  uint8_t *out,
                                                                  size_t out_size)
{
    if (!pow || !out) return OP_NULL_PTR;
    if (out_size < MINI_POW_CHALLENGE_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    serialize_u64_be(pow->challenge_id, out);
    serialize_u16_be(pow->row, out + UINT64_SIZE);
    serialize_u16_be(pow->col, out + UINT64_SIZE + UINT16_SIZE);
    serialize_u16_be(pow->iteration, out + UINT64_SIZE + 2 * UINT16_SIZE);
    return OP_SUCCESS;
}

MINI_POW_CHALLENGE_INLINE OpStatus_t mini_pow_challenge_deserialize(const uint8_t *in,
                                                                    size_t in_size,
                                                                    mini_pow_challenge_t *pow)
{
    if (!pow || !in) return OP_NULL_PTR;
    if (in_size < MINI_POW_CHALLENGE_SERIALIZED_SIZE) return OP_BUF_TOO_SMALL;

    deserialize_u64_be(in, &pow->challenge_id, sizeof(uint64_t));
    deserialize_u16_be(in + UINT64_SIZE, &pow->row, sizeof(uint16_t));
    deserialize_u16_be(in + UINT64_SIZE + UINT16_SIZE, &pow->col, sizeof(uint16_t));
    deserialize_u16_be(in + UINT64_SIZE + 2 * UINT16_SIZE, &pow->iteration, sizeof(uint16_t));
    return OP_SUCCESS;
}

MINI_POW_CHALLENGE_INLINE OpStatus_t generate_mini_pow_Challenge(uint64_t challenge_id,
                                                                 uint16_t row,
                                                                 uint16_t col,
                                                                 uint16_t iteration,
                                                                 mini_pow_challenge_t *pow)
{
    if (!pow) return OP_NULL_PTR;
    pow->challenge_id = challenge_id;
    pow->row = row;
    pow->col = col;
    pow->iteration = iteration;
    return OP_SUCCESS;
}

#endif // MINI_POW_CHALLENGE_H
