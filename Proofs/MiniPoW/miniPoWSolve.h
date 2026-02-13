#ifndef MINI_POW_SOLVE_H
#define MINI_POW_SOLVE_H

#include "datatype/uint256_t.h"

#if !defined(__linux__)
#error "This implementation is Linux optimized only"
#endif


#define MINI_POW_SOLVE_INLINE static inline __attribute__((always_inline))

typedef struct __attribute__((aligned(32))) {
    uint256 challenge;   // 32 bytes
    uint64_t nonce;      // 8 bytes
    uint8_t complexity;  // 1 byte
    uint8_t reserved[7]; // padding to make 32-byte multiple
} mini_pow_solve_t;








#endif // MINI_POW_SOLVE_H