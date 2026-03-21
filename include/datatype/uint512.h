#ifndef UINT512_H
#define UINT512_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <endian.h>
#include "datatype/uint256_t.h"
#include "datatype/OpStatus.h"
#include "util/Size_Offsets.h"


#if !defined(__linux__)
#error "This implementation is Linux optimized only"
#endif

/* Force aggressive inlining */
#define U512_INLINE static inline __attribute__((always_inline))

/* Align for cache/SIMD */
typedef struct __attribute__((aligned(32))) {
    uint64_t w[8];   /* little-endian word order, 8*64 = 512 bits */
} uint512;

/* ---------- Constructors ---------- */

U512_INLINE void uint512_zero(uint512 *u)
{
    for (int i = 0; i < 8; ++i) u->w[i] = 0;
}

U512_INLINE void uint512_from_u64(uint512 *u, uint64_t v)
{
    u->w[0] = v;
    for (int i = 1; i < 8; ++i) u->w[i] = 0;
}

/* ---------- Comparison ---------- */

U512_INLINE bool uint512_equal(const uint512 *a, const uint512 *b)
{
    uint64_t res = 0;
    for (int i = 0; i < 8; ++i)
        res |= (a->w[i] ^ b->w[i]);
    return res == 0;
}

U512_INLINE bool uint512_not_equal(const uint512 *a, const uint512 *b)
{
    return !uint512_equal(a, b);
}

/* ---------- Bit Access ---------- */

U512_INLINE bool uint512_get_bit(const uint512 *u, unsigned bit)
{
    return (u->w[bit >> 6] >> (bit & 63)) & 1;
}

U512_INLINE void uint512_set_bit(uint512 *u, unsigned bit, bool val)
{
    uint64_t mask = 1ULL << (bit & 63);
    if (val)
        u->w[bit >> 6] |= mask;
    else
        u->w[bit >> 6] &= ~mask;
}

/* ---------- Copy ---------- */

U512_INLINE void uint512_copy(uint512 *dst, const uint512 *src)
{
    memcpy(dst, src, sizeof(uint512));
}


/* ---------- Serialize / Deserialize ---------- */

U512_INLINE OpStatus_t uint512_serialize(const uint512 *u, uint8_t *buf, size_t buf_len)
{
    if (!u || !buf) return OP_NULL_PTR;
    if (buf_len < UINT512_SIZE) return OP_BUF_TOO_SMALL;

    for (int i = 0; i < 8; ++i)
    {
        uint64_t w_be = htobe64(u->w[i]);
        memcpy(buf + i*8, &w_be, 8);
    }

    return OP_SUCCESS;
}

U512_INLINE OpStatus_t uint512_deserialize(uint512 *u, const uint8_t *buf, size_t buf_len)
{
    if (!u || !buf) return OP_NULL_PTR;
    if (buf_len < UINT512_SIZE) return OP_BUF_TOO_SMALL;

    for (int i = 0; i < 8; ++i)
    {
        uint64_t w_be;
        memcpy(&w_be, buf + i*8, 8);
        u->w[i] = be64toh(w_be);
    }

    return OP_SUCCESS;
}


U512_INLINE void uint512_from_two_uint256(uint512 *out, const uint256 *high, const uint256 *low)
{
    if (!out || !high || !low) return;

    memcpy(out->w, high->w, sizeof(uint256));          // w[0..3] = high
    memcpy(out->w + 4, low->w, sizeof(uint256));      // w[4..7] = low
}

#endif
