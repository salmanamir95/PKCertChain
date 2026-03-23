#ifndef PKCERTCHAIN_H
#define PKCERTCHAIN_H

#include <stdint.h>
#include "blockchain/block.h"

typedef struct __attribute__((aligned(4))) {
    block blocks[100]; //148
    uint32_t index;
} PKCertChain;

#endif // PKCERTCHAIN_H
