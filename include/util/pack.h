#ifndef UTIL_PACK_H
#define UTIL_PACK_H

#include <endian.h>
#include <stdint.h>
#include <string.h>

#include "datatype/uint256_t.h"

static inline void pack_u64_be(uint64_t v, uint8_t out[8])
{
    uint64_t be = htobe64(v);
    memcpy(out, &be, 8);
}

static inline void pack_uint256_be(const uint256 *u, uint8_t *out32)
{
    for (int i = 0; i < 4; ++i) {
        uint64_t be = htobe64(u->w[i]);
        memcpy(out32 + (i * 8), &be, 8);
    }
}

static inline void pack_two_uint256_be(const uint256 *a, const uint256 *b, uint8_t *out64)
{
    pack_uint256_be(a, out64);
    pack_uint256_be(b, out64 + 32);
}

#endif // UTIL_PACK_H
