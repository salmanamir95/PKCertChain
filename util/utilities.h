#ifndef UTILITIES_H
#define UTILITIES_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

#include "datatype/uint256_t.h"

#define HASH256_INLINE static inline __attribute__((always_inline))

/*
 * Zero-copy hashing for arbitrary memory buffer
 */
HASH256_INLINE void hash256_buffer(const void *ptr,
                                   size_t len,
                                   uint256 *out)
{
    SHA256((const unsigned char *)ptr,
           len,
           (unsigned char *)out);
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
           (unsigned char *)out);
}


/*
 * Convenience macro to mimic C++ template behavior
 *
 * Example:
 *     struct foo f;
 *     HASH256_OF(f, &result);
 */
#define HASH256_OF(obj, out_ptr) \
    hash256_object(&(obj), sizeof(obj), (out_ptr))


#endif
