#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include "datatype/uint256_t.h"
#include "blockchain/certificate.h"

#define BLOCK_INLINE static inline __attribute__((always_inline))

/*
 * PKCertChain Block
 * - Aligned 32 bytes for cache efficiency
 * - Uses fixed-width integers for determinism
 * - All serialization to network byte order
 */

typedef struct __attribute__((aligned(32))) {
    certificate cert;     // 64 bytes: pubSignKey + pubEncKey + id
    uint64_t timestamp;   // monotonic time, canonical 64-bit
    uint8_t  index;       // block index (small network)
    uint8_t  reserved[7]; // padding to maintain 32-byte alignment
} block;

#endif // BLOCK_H
