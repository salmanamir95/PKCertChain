#ifndef LINUXUTILS_H
#define LINUXUTILS_H

#include "pkcertchain_config.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "datatype/OpStatus.h"
#include "datatype/uint256_t.h"

#ifndef UTIL_INLINE
#define UTIL_INLINE static inline __attribute__((always_inline))
#endif

#define PKCERTCHAIN_WALLET_SUBDIR ".pkcertchain/wallet"
#define PKCERTCHAIN_BASE_SUBDIR   ".pkcertchain"
#define PKCERTCHAIN_SIGN_PRIV_FILE "sign_priv.key"
#define PKCERTCHAIN_SIGN_PUB_FILE  "sign_pub.key"
#define PKCERTCHAIN_ENC_PRIV_FILE  "enc_priv.key"
#define PKCERTCHAIN_ENC_PUB_FILE   "enc_pub.key"

/*
 * Check whether ~/.pkcertchain/wallet exists.
 *
 * Returns:
 *   - true  if setup is needed (missing path)
 *   - false if path exists
 */
UTIL_INLINE bool need_pkcertchain_setup(void)
{
    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') return true;

    char path[512];
    if (snprintf(path, sizeof(path), "%s/%s", home, PKCERTCHAIN_WALLET_SUBDIR) <= 0) return true;

    struct stat st;
    if (stat(path, &st) != 0) return true;
    if (!S_ISDIR(st.st_mode)) return true;

    return false;
}

/*
 * Create ~/.pkcertchain/wallet with mode 700 (non-interactive).
 *
 * Returns:
 *   - OP_SUCCESS on success
 *   - OP_NEEDS_PRIVILEGE if permission is denied
 *   - OP_INVALID_INPUT on failure
 */
UTIL_INLINE OpStatus_t create_wallet(void)
{
    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') return OP_INVALID_INPUT;

    char base_path[512];
    char wallet_path[512];
    if (snprintf(base_path, sizeof(base_path), "%s/%s", home, PKCERTCHAIN_BASE_SUBDIR) <= 0) return OP_INVALID_INPUT;
    if (snprintf(wallet_path, sizeof(wallet_path), "%s/%s", home, PKCERTCHAIN_WALLET_SUBDIR) <= 0) return OP_INVALID_INPUT;

    // Create ~/.pkcertchain if needed
    if (mkdir(base_path, 0700) != 0 && errno != EEXIST) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    // Create ~/.pkcertchain/wallet if needed
    if (mkdir(wallet_path, 0700) != 0 && errno != EEXIST) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    // Ensure permissions are correct (best-effort)
    if (chmod(wallet_path, 0700) != 0) {
        if (errno == EACCES || errno == EPERM) return OP_NEEDS_PRIVILEGE;
        return OP_INVALID_INPUT;
    }

    return OP_SUCCESS;
}

/*
 * Ensure wallet directory exists with correct permissions.
 *
 * Returns:
 *   - OP_SUCCESS if already present or created
 *   - OP_NEEDS_PRIVILEGE if permission denied
 *   - OP_INVALID_INPUT on other failures
 */
UTIL_INLINE OpStatus_t ensure_wallet_dir(void)
{
    if (!need_pkcertchain_setup()) return OP_SUCCESS;
    return create_wallet();
}

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
                                           const uint256 *pub_key)
{
    if (!priv_key || !pub_key) return OP_NULL_PTR;

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

    st = save_file_0600(priv_path, priv_buf, sizeof(priv_buf));
    if (st != OP_SUCCESS) return st;
    st = save_file_0600(pub_path, pub_buf, sizeof(pub_buf));
    if (st != OP_SUCCESS) return st;

    return OP_SUCCESS;
}

/*
 * Save Ed25519 signing keys to ~/.pkcertchain/wallet with 0600 permissions.
 */
UTIL_INLINE OpStatus_t save_sign_keys(const uint256 *priv_key, const uint256 *pub_key)
{
    return save_keys_to_wallet(PKCERTCHAIN_SIGN_PRIV_FILE, PKCERTCHAIN_SIGN_PUB_FILE, priv_key, pub_key);
}

/*
 * Save X25519 encryption keys to ~/.pkcertchain/wallet with 0600 permissions.
 */
UTIL_INLINE OpStatus_t save_enc_keys(const uint256 *priv_key, const uint256 *pub_key)
{
    return save_keys_to_wallet(PKCERTCHAIN_ENC_PRIV_FILE, PKCERTCHAIN_ENC_PUB_FILE, priv_key, pub_key);
}

#endif // LINUXUTILS_H
