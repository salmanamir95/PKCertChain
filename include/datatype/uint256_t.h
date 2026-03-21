#ifndef UINT256_H
#define UINT256_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "datatype/OpStatus.h"
#if !defined(__linux__)
#error "This implementation is Linux optimized only"
#endif

/* Force aggressive inlining */
#define U256_INLINE static inline __attribute__((always_inline))

/* Align for better cache / SIMD */
typedef struct __attribute__((aligned(32))) {
    uint64_t w[4];   /* little-endian word order */
} uint256;


/* ---------- Constructors ---------- */

U256_INLINE void uint256_zero(uint256 *u)
{
    u->w[0] = 0;
    u->w[1] = 0;
    u->w[2] = 0;
    u->w[3] = 0;
}

U256_INLINE void uint256_from_u64(uint256 *u, uint64_t v)
{
    u->w[0] = v;
    u->w[1] = 0;
    u->w[2] = 0;
    u->w[3] = 0;
}


/* ---------- Comparison ---------- */

U256_INLINE bool uint256_equal(const uint256 *a,
                               const uint256 *b)
{
    /* branchless */
    return ((a->w[0] ^ b->w[0]) |
            (a->w[1] ^ b->w[1]) |
            (a->w[2] ^ b->w[2]) |
            (a->w[3] ^ b->w[3])) == 0;
}

U256_INLINE bool uint256_not_equal(const uint256 *a,
                                   const uint256 *b)
{
    return !uint256_equal(a, b);
}


/* ---------- Bit Access ---------- */

U256_INLINE bool uint256_get_bit(const uint256 *u, unsigned bit)
{
    return (u->w[bit >> 6] >> (bit & 63)) & 1;
}

U256_INLINE void uint256_set_bit(uint256 *u,
                                 unsigned bit,
                                 bool val)
{
    uint64_t mask = 1ULL << (bit & 63);

    if (val)
        u->w[bit >> 6] |= mask;
    else
        u->w[bit >> 6] &= ~mask;
}


/* ---------- Copy ---------- */

U256_INLINE void uint256_copy(uint256 *dst,
                              const uint256 *src)
{
    /* lets compiler vectorize */
    memcpy(dst, src, sizeof(uint256));
}


#define UINT256_SIZE 32  // 4 * 8 bytes

U256_INLINE OpStatus_t uint256_serialize(const uint256 *u, uint8_t *buf, size_t buf_len)
{
    if (!u || !buf) return OP_NULL_PTR;          // null pointer check
    if (buf_len < UINT256_SIZE) return OP_BUF_TOO_SMALL; // buffer too small

    for (int i = 0; i < 4; ++i)
    {
        uint64_t w_be = htobe64(u->w[i]);       // convert to big-endian
        memcpy(buf + i*8, &w_be, 8);
    }

    return OP_SUCCESS;
}



U256_INLINE OpStatus_t uint256_deserialize(uint256 *u, const uint8_t *buf, size_t buf_len)
{
    if (!u || !buf) return OP_NULL_PTR;            // null pointer check
    if (buf_len < UINT256_SIZE) return OP_BUF_TOO_SMALL; // buffer too small

    for (int i = 0; i < 4; ++i)
    {
        uint64_t w_be;
        memcpy(&w_be, buf + i*8, 8);
        u->w[i] = be64toh(w_be);                  // convert back to host endianness
    }

    return OP_SUCCESS;
}


#endif
