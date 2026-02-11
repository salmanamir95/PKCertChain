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

#define HASH256_INLINE static inline __attribute__((always_inline))

/*
 * Zero-copy hashing for arbitrary memory buffer
 * Produces a 256-bit hash into uint256 struct
 */
HASH256_INLINE void hash256_buffer(const void *ptr,
                                   size_t len,
                                   uint256 *out)
{
    SHA256((const unsigned char *)ptr,
           len,
           (unsigned char *)out->w); // write directly into uint256
}

/*
 * Generic object hashing (zero-copy)
 * Caller guarantees object is POD / trivially copyable
 */
HASH256_INLINE void hash256_object(const void *obj,
                                   size_t size,
                                   uint256 *out)
{
    SHA256((const unsigned char *)obj,
           size,
           (unsigned char *)out->w); // write directly into uint256
}

/*
 * Convenience macro to mimic C++ template behavior
 *
 * Usage:
 *     struct foo f;
 *     uint256 result;
 *     HASH256_OF(f, &result);
 */
#define HASH256_OF(obj, out_ptr) \
    hash256_object(&(obj), sizeof(obj), (out_ptr))

#endif // UTILITIES_H
