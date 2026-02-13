#ifndef UTILITIES_H
#define UTILITIES_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

#include "datatype/uint256_t.h"

#if !defined(__linux__)
#error "This implementation is Linux optimized only"
#endif

#define UTIL_INLINE static inline __attribute__((always_inline))

/*
 * Hash a raw buffer and write directly into uint256
 *
 * Input:
 *   - buf: pointer to bytes
 *   - len: length of the buffer
 *   - out: pointer to uint256 to store hash
 *
 * Output:
 *   - writes 32-byte SHA256 directly into out->w
 */
UTIL_INLINE void hash256_buffer(const uint8_t *buf, size_t len, uint256 *out)
{
    if (!buf || !out) return;               // optional safety check
    SHA256(buf, len, (unsigned char *)out->w);
}



#endif // UTILITIES_H
