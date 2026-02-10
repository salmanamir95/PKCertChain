#ifndef CERTIFICATE_H
#define CERTIFICATE_H
#include <cstdint>
#include "datatype/uint256_t.h"
#define CERT_INLINE static inline __attribute__((always_inline))

typedef struct __attribute__((aligned(32))) {
    uint256 pubSignKey;
    uint256 pubEncKey;
    uint8_t id;
} certificate;

#endif 