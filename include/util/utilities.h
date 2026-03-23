#ifndef UTILITIES_H
#define UTILITIES_H

#include "pkcertchain_config.h"


#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "datatype/uint256_t.h"
#include "datatype/uint512.h"
#include "datatype/OpStatus.h"
#include "util/Size_Offsets.h"

#define UTIL_INLINE static inline __attribute__((always_inline))

/*
 * Hash a raw buffer and write directly into uint256
 *
 * Input:
 *   - buf: pointer to bytes
 *   - len: length of the buffer
 *   - out: pointer to uint256 to store hash
 *
 * Output:
 *   - writes 32-byte SHA256 directly into out->w
 */
UTIL_INLINE void hash256_buffer(const uint8_t *buf, size_t len, uint256 *out)
{
    if (!buf || !out) return;               // optional safety check
    SHA256(buf, len, (unsigned char *)out->w);
}


UTIL_INLINE uint16_t clz256(const uint256 *hash)
{
    uint32_t count = 0;

    for (int i = 0; i < 4; i++) {
        uint64_t w = hash->w[i];

        if (w == 0) {
            count += 64;
        } else {
            count += __builtin_clzll(w);
            break;
        }
    }

    return count;
}

/*
 * Sign a raw buffer using Ed25519.
 *
 * Input:
 *   - in: pointer to bytes
 *   - in_len: length of the buffer
 *   - priv_key: pointer to uint256 private key (32-byte seed)
 *   - out: pointer to uint512 to store 64-byte signature
 *
 * Returns:
 *   - OP_SUCCESS on success
 *   - OP_NULL_PTR if a required pointer is NULL
 *   - OP_INVALID_INPUT on signing failure
 */
UTIL_INLINE OpStatus_t sign_buffer_ed25519(const uint8_t *in, size_t in_len, const uint256 *priv_key, uint512 *out)
{
    if (!out) return OP_NULL_PTR;
    uint512_zero(out);
    if (!in || !priv_key) return OP_NULL_PTR;

    uint8_t key_buf[UINT256_SIZE];
    if (uint256_serialize_be(priv_key, key_buf, sizeof(key_buf)) != OP_SUCCESS) return OP_INVALID_INPUT;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, key_buf, sizeof(key_buf));
    if (!pkey) return OP_INVALID_INPUT;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return OP_INVALID_INPUT;
    }

    size_t sig_len = UINT512_SIZE;
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestSign(mdctx, (unsigned char *)out->w, &sig_len, in, in_len) == 1 &&
        sig_len == UINT512_SIZE) {
        // success
    } else {
        uint512_zero(out);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return OP_INVALID_INPUT;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return OP_SUCCESS;
}



#endif // UTILITIES_H
