#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include "pkcertchain_config.h"


#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "datatype/uint256_t.h"
#include "datatype/uint512.h"
#include "Global_Size_Offsets.h"
#include "util/NetworkSerialization.h"
#include "util/NetworkSerialization.h"
#include "util/SignUtils.h"
#include "PKCertChain/certificate.h"
#include "enums/OpStatus.h"


#define CERT_INLINE static inline __attribute__((always_inline))

/*
 * Certificate structure:
 * - 4-byte aligned (32-bit alignment)
 * - Serialized size is 68 bytes
 * - In-memory size is typically 72 bytes on 64-bit due to uint64 alignment
 */



CERT_INLINE void cert_init(certificate * cert){
    uint256_zero(&cert->pubEncKey);
    uint256_zero(&cert->pubSignKey);
    ipv6_zero(&cert->id);
    memset(cert->reserved, 0, sizeof(cert->reserved));
}

CERT_INLINE const uint256* cert_get_pubSignKey_ptr(const certificate *cert) {
    return &cert->pubSignKey;
}


CERT_INLINE const uint256* cert_get_pubEncKey(const certificate * cert){
    return &cert->pubEncKey;
}

CERT_INLINE const ipv6_t* cert_get_id(const certificate * cert){
    return &cert->id;
}

CERT_INLINE void cert_set_pubSignKey(certificate * cert, const uint256 * key){
    cert->pubSignKey = *key;
}

CERT_INLINE void cert_set_pubEncKey(certificate * cert, const uint256 * key){
    cert->pubEncKey = *key;
}

CERT_INLINE void cert_set_id(certificate * cert, const ipv6_t* id){
    cert->id = *id;
}

CERT_INLINE void cert_copy(certificate * dst, const certificate * src){
    uint256_copy(&dst->pubSignKey, &src->pubSignKey);
    uint256_copy(&dst->pubEncKey, &src->pubEncKey);
    dst->id = src->id;
    memset(dst->reserved, 0, sizeof(dst->reserved));
}

/* Moved to NetworkSerialization.h */


/* Moved to NetworkSerialization.h */


CERT_INLINE OpStatus_t hash_certificate(const certificate *cert, uint256 *out)
{
    if (!cert || !out) return OP_NULL_PTR;

    uint8_t buf[CERT_SIZE];
    OpStatus_t st = cert_serialize(cert, buf, sizeof(buf));
    if (st != OP_SUCCESS) return st;

    hash256_buffer(buf, sizeof(buf), out);
    return OP_SUCCESS;
}

CERT_INLINE OpStatus_t cert_sign(const certificate *cert, const uint256 *priv_key, uint512 *out_sig)
{
    if (!cert || !priv_key || !out_sig) return OP_NULL_PTR;

    uint8_t buf[CERT_SIZE];
    OpStatus_t st = cert_serialize(cert, buf, sizeof(buf));
    if (st != OP_SUCCESS) return st;

    return sign_buffer_ed25519(buf, sizeof(buf), priv_key, out_sig);
}


#endif // CERTIFICATE_H
