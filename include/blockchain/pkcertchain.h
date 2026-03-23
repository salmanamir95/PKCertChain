#ifndef PKCERTCHAIN_H
#define PKCERTCHAIN_H

#include "pkcertchain_config.h"



#ifndef PKCERTCHAIN_INLINE
#define PKCERTCHAIN_INLINE static inline __attribute__((always_inline))
#endif

#include <stdint.h>
#include "blockchain/block.h"

typedef struct __attribute__((aligned(4))) {
    block blocks[100]; //148
    uint32_t index;
} PKCertChain;

#endif // PKCERTCHAIN_H
