#ifndef BLOCK_H
#define BLOCK_H
#include <cstdint>
#include "datatype/uint256_t.h"
#include "blockchain/certificate.h"
#include <time.h>
#define BLOCK_INLINE static inline __attribute__((always_inline))

//we can use 32 bit flag for small variables like index

typedef struct __attribute__((aligned(32))) {
    certificate cert;
    time_t time;
    uint8_t index;
} block;

#endif //BLOKC_H    