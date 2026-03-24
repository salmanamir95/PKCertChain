#ifndef LINUXUTILS_H
#define LINUXUTILS_H

#include "pkcertchain_config.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include "datatype/OpStatus.h"
#include "datatype/uint256_t.h"
#include "util/EncUtils.h"
#include "util/WalletSetup.h"

#ifndef UTIL_INLINE
#define UTIL_INLINE static inline __attribute__((always_inline))
#endif

#define PKCERTCHAIN_SIGN_PRIV_FILE "sign_priv.key"
#define PKCERTCHAIN_SIGN_PUB_FILE  "sign_pub.key"
#define PKCERTCHAIN_ENC_PRIV_FILE  "enc_priv.key"
#define PKCERTCHAIN_ENC_PUB_FILE   "enc_pub.key"

UTIL_INLINE OpStatus_t save_file_0600(const char *path, const uint8_t *buf, size_t len)
{
    if (!path || !buf || len == 0) return OP_INVALID_INPUT;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    size_t written = 0;
    while (written < len) {
        ssize_t rc = write(fd, buf + written, len - written);
        if (rc < 0) {
            int err = errno;
            close(fd);
            if (err == EACCES || err == EPERM) return OP_NEEDS_PRIVILEGE;
            return OP_INVALID_INPUT;
        }
        written += (size_t)rc;
    }

    if (close(fd) != 0) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    return OP_SUCCESS;
}

UTIL_INLINE OpStatus_t save_keys_to_wallet(const char *priv_name,
                                           const char *pub_name,
                                           const uint256 *priv_key,
                                           const uint256 *pub_key,
                                           const char *password,
                                           size_t password_len)
{
    if (!priv_key || !pub_key) return OP_NULL_PTR;
    if (!password || password_len == 0) return OP_INVALID_INPUT;

    OpStatus_t st = ensure_wallet_dir();
    if (st != OP_SUCCESS) return st;

    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') return OP_INVALID_INPUT;

    char priv_path[512];
    char pub_path[512];
    if (snprintf(priv_path, sizeof(priv_path), "%s/%s/%s", home, PKCERTCHAIN_WALLET_SUBDIR, priv_name) <= 0)
        return OP_INVALID_INPUT;
    if (snprintf(pub_path, sizeof(pub_path), "%s/%s/%s", home, PKCERTCHAIN_WALLET_SUBDIR, pub_name) <= 0)
        return OP_INVALID_INPUT;

    uint8_t priv_buf[UINT256_SIZE];
    uint8_t pub_buf[UINT256_SIZE];
    if (uint256_serialize_be(priv_key, priv_buf, sizeof(priv_buf)) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (uint256_serialize_be(pub_key, pub_buf, sizeof(pub_buf)) != OP_SUCCESS) return OP_INVALID_INPUT;

    uint8_t *enc_priv = NULL;
    size_t enc_priv_len = 0;
    uint8_t *enc_pub = NULL;
    size_t enc_pub_len = 0;

    st = LocalSaveEncrypt(priv_buf, sizeof(priv_buf), password, password_len, &enc_priv, &enc_priv_len);
    if (st != OP_SUCCESS) return st;
    st = LocalSaveEncrypt(pub_buf, sizeof(pub_buf), password, password_len, &enc_pub, &enc_pub_len);
    if (st != OP_SUCCESS) {
        free(enc_priv);
        return st;
    }

    st = save_file_0600(priv_path, enc_priv, enc_priv_len);
    if (st != OP_SUCCESS) {
        free(enc_priv);
        free(enc_pub);
        return st;
    }
    st = save_file_0600(pub_path, enc_pub, enc_pub_len);
    if (st != OP_SUCCESS) return st;

    free(enc_priv);
    free(enc_pub);
    return OP_SUCCESS;
}

/*
 * Save Ed25519 signing keys to ~/.pkcertchain/wallet with 0600 permissions.
 */
UTIL_INLINE OpStatus_t save_sign_keys(const uint256 *priv_key, const uint256 *pub_key,
                                      const char *password, size_t password_len)
{
    return save_keys_to_wallet(PKCERTCHAIN_SIGN_PRIV_FILE, PKCERTCHAIN_SIGN_PUB_FILE,
                               priv_key, pub_key, password, password_len);
}

/*
 * Save X25519 encryption keys to ~/.pkcertchain/wallet with 0600 permissions.
 */
UTIL_INLINE OpStatus_t save_enc_keys(const uint256 *priv_key, const uint256 *pub_key,
                                     const char *password, size_t password_len)
{
    return save_keys_to_wallet(PKCERTCHAIN_ENC_PRIV_FILE, PKCERTCHAIN_ENC_PUB_FILE,
                               priv_key, pub_key, password, password_len);
}

#endif // LINUXUTILS_H
