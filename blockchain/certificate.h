#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <stdint.h>
#include "datatype/uint256_t.h"

#define CERT_INLINE static inline __attribute__((always_inline))

/*
 * Certificate structure:
 * - Fixed-size 128 bytes for cache alignment and zero-copy
 * - Deterministic layout for serialization
 * - Future-proof padding
 */

typedef struct __attribute__((aligned(32))) {
    uint256 pubSignKey;    // 32 bytes
    uint256 pubEncKey;     // 32 bytes
    uint8_t  id;           // 1 byte node id
    uint8_t  reserved[95]; // padding to make struct 128 bytes
} certificate;

#endif // CERTIFICATE_H
