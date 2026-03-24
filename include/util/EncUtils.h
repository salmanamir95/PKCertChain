#ifndef ENCUTILS_H
#define ENCUTILS_H

#include "pkcertchain_config.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>

#include "datatype/uint256_t.h"
#include "datatype/OpStatus.h"
#include "util/Size_Offsets.h"
#include "util/LinuxUtils.h"

#ifndef UTIL_INLINE
#define UTIL_INLINE static inline __attribute__((always_inline))
#endif

/*
 * Generate X25519 encryption keypair.
 *
 * Output:
 *   - out_priv: 32-byte private key
 *   - out_pub: 32-byte public key
 */
UTIL_INLINE OpStatus_t GenerateEncKeys(uint256 *out_priv, uint256 *out_pub)
{
    if (!out_priv || !out_pub) return OP_NULL_PTR;
    if (need_pkcertchain_setup()) {
        OpStatus_t st = create_wallet();
        if (st != OP_SUCCESS) return st;
    }
    uint256_zero(out_priv);
    uint256_zero(out_pub);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return OP_INVALID_INPUT;
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return OP_INVALID_INPUT;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0 || !pkey) {
        EVP_PKEY_CTX_free(pctx);
        return OP_INVALID_INPUT;
    }

    size_t priv_len = UINT256_SIZE;
    size_t pub_len = UINT256_SIZE;
    if (EVP_PKEY_get_raw_private_key(pkey, (unsigned char *)out_priv->w, &priv_len) != 1 ||
        EVP_PKEY_get_raw_public_key(pkey, (unsigned char *)out_pub->w, &pub_len) != 1 ||
        priv_len != UINT256_SIZE || pub_len != UINT256_SIZE) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        uint256_zero(out_priv);
        uint256_zero(out_pub);
        return OP_INVALID_INPUT;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return OP_SUCCESS;
}

#endif // ENCUTILS_H
