#ifndef POC_H
#define POC_H
#include <datatype/uint256_t.h>
#define POW_INLINE static inline __attribute__((always_inline))

typedef struct __attribute__((aligned(32))) {
    uint256 challenge;   // 256-bit challenge
    uint8_t complexity;  // 0-255 bits
} pow_t;

POW_INLINE pow_t generate_Challenge(void* block){

}

#endif //POC_H