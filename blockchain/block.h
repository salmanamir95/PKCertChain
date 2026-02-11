#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include "datatype/uint256_t.h"
#include "blockchain/certificate.h"

#if !defined(__linux__)
#error "This implementation is Linux optimized only"
#endif


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

BLOCK_INLINE void block_init(block * blk){
    cert_init(&blk->cert);
    blk->timestamp = 0;
    blk->index = 0;
    memset(blk->reserved, 0, sizeof(blk->reserved));
}

BLOCK_INLINE const certificate* block_get_cert_ptr(const block * blk){
    return &blk->cert;
}

BLOCK_INLINE uint64_t block_get_timestamp(const block * blk){
    return blk->timestamp;
}

BLOCK_INLINE uint8_t block_get_index(const block * blk){
    return blk->index;
}

BLOCK_INLINE void block_set_cert(block * blk, const certificate * cert){
    cert_copy(&blk->cert, cert);
}

BLOCK_INLINE void block_set_timestamp(block * blk, uint64_t timestamp){
    blk->timestamp = timestamp;
}

BLOCK_INLINE void block_set_index(block * blk, uint8_t index){
    blk->index = index;
}

BLOCK_INLINE void block_copy(block * dst, const block * src){
    cert_copy(&dst->cert, &src->cert);
    dst->timestamp = src->timestamp;
    dst->index = src->index;
    memset(dst->reserved, 0, sizeof(dst->reserved));
}


#endif // BLOCK_H
