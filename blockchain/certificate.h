#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <stdint.h>
#include "datatype/uint256_t.h"
#include "datatype/OpStatus.h"


#if !defined(__linux__)
#error "This implementation is Linux optimized only"
#endif


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
    uint8_t  reserved[31]; // padding
} certificate;

CERT_INLINE void cert_init(certificate * cert){
    uint256_zero(&cert->pubEncKey);
    uint256_zero(&cert->pubSignKey);
    cert->id = 0;
    memset(cert->reserved, 0, sizeof(cert->reserved));
}

CERT_INLINE const uint256* cert_get_pubSignKey_ptr(const certificate *cert) {
    return &cert->pubSignKey;
}


CERT_INLINE const uint256* cert_get_pubEncKey(const certificate * cert){
    return &cert->pubEncKey;
}

CERT_INLINE uint8_t cert_get_id(const certificate * cert){
    return cert->id;
}

CERT_INLINE void cert_set_pubSignKey(certificate * cert, const uint256 * key){
    cert->pubSignKey = *key;
}

CERT_INLINE void cert_set_pubEncKey(certificate * cert, const uint256 * key){
    cert->pubEncKey = *key;
}

CERT_INLINE void cert_set_id(certificate * cert, uint8_t id){
    cert->id = id;
}

CERT_INLINE void cert_copy(certificate * dst, const certificate * src){
    uint256_copy(&dst->pubSignKey, &src->pubSignKey);
    uint256_copy(&dst->pubEncKey, &src->pubEncKey);
    dst->id = src->id;
    memset(dst->reserved, 0, sizeof(dst->reserved));
}

#define CERT_SIZE 65

CERT_INLINE OpStatus_t cert_serialize(certificate *cert, uint8_t* buf, size_t buf_len) {
    if (!cert || !buf) return OP_NULL_PTR;             // null pointer check
    if (buf_len < CERT_SIZE) return OP_BUF_TOO_SMALL;  // buffer too small

    OpStatus_t status =  uint256_serialize(&cert->pubSignKey, buf, sizeof(buf));        // bytes 0..31
    if (status != OP_SUCCESS) return status;

    status = uint256_serialize(&cert->pubEncKey, buf + 32, sizeof(buf));    // bytes 32..63
    if (status != OP_SUCCESS) return status;

    buf[64] = cert->id;                               // byte 64

    return OP_SUCCESS;
}



CERT_INLINE OpStatus_t cert_deserialize(certificate *cert, const uint8_t* buf, size_t buf_len) {
    if (!cert || !buf) return OP_NULL_PTR;             // null pointer check
    if (buf_len < CERT_SIZE) return OP_BUF_TOO_SMALL;  // buffer too small

    OpStatus_t status = uint256_deserialize(&cert->pubSignKey, buf, 32);  // bytes 0..31
    if (status != OP_SUCCESS) return status;

    status = uint256_deserialize(&cert->pubEncKey, buf + 32, 32);         // bytes 32..63
    if (status != OP_SUCCESS) return status;

    cert->id = buf[64];  // restore id

    return OP_SUCCESS;
}



#endif // CERTIFICATE_H
