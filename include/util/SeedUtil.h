#ifndef SEED_UTIL_H
#define SEED_UTIL_H

#include "pkcertchain_config.h"
#include "blockchain/certificate.h"
#include "util/utilities.h"
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#ifndef UTIL_INLINE
#define UTIL_INLINE static inline __attribute__((always_inline))
#endif

UTIL_INLINE OpStatus_t mini_pow_seed_gen(const certificate *new_cert, const uint256 *lastBlockHash,
                                         const uint32_t *sessionId, const uint32_t *challengeID, uint256 *seed)
{
    if (!new_cert || !lastBlockHash || !sessionId || !challengeID || !seed)
        return OP_INVALID_INPUT;

    uint8_t *buf = new uint8_t[CERT_SIZE + UINT256_SIZE + UINT32_SIZE + UINT32_SIZE];
    OpStatus_t status = cert_serialize(new_cert, buf, CERT_SIZE);
    if (status != OP_SUCCESS)
    {
        delete[] buf;
        return status;
    }
    status = uint256_serialize_be(lastBlockHash, buf + CERT_SIZE, UINT256_SIZE);
    if (status != OP_SUCCESS)
    {
        delete[] buf;
        return status;
    }
    serialize_u32_be(*sessionId, buf + CERT_SIZE + UINT256_SIZE);
    serialize_u32_be(*challengeID, buf + CERT_SIZE + UINT256_SIZE + UINT32_SIZE);

    hash256_buffer(buf, CERT_SIZE + UINT256_SIZE + UINT32_SIZE + UINT32_SIZE, seed);
    if (!seed)
    {
        delete[] buf;
        return OP_INVALID_STATE;
    }
    delete[] buf;
    return OP_SUCCESS;
}


UTIL_INLINE OpStatus_t mini_pow_csprng(const uint256* seed, const uint32_t* iteration, uint16_t* out_val)
{
    if (!seed || !iteration || !out_val) return OP_INVALID_INPUT;

    uint8_t iterbuf[UINT32_SIZE];
    serialize_u32_be(*iteration, iterbuf);  // iteration as personalization
    uint8_t seedbuf[UINT256_SIZE];
    uint256_serialize_be(seed, seedbuf, UINT256_SIZE);
    // Create HMAC_DRBG
    RAND_DRBG* drbg = RAND_DRBG_new(NID_hmacWithSHA256, 0, NULL);
    if (!drbg) return OP_INVALID_STATE;

    // Instantiate DRBG with seed as entropy + iteration as personalization
    if (!RAND_DRBG_instantiate(drbg, seedbuf, UINT256_SIZE, iterbuf, UINT32_SIZE)) {
        RAND_DRBG_free(drbg);
        return OP_INVALID_STATE;
    }

    // Generate 4 bytes to make uint32
    uint32_t temp;
    if (RAND_DRBG_bytes(drbg, (unsigned char*)&temp, sizeof(temp), 0) <= 0) {
        RAND_DRBG_uninstantiate(drbg);
        RAND_DRBG_free(drbg);
        return OP_INVALID_STATE;
    }

    // Cleanup
    RAND_DRBG_uninstantiate(drbg);
    RAND_DRBG_free(drbg);

    // Return lower 16 bits
    *out_val = (uint16_t)(temp & 0xFFFF);

    return OP_SUCCESS;
}


#endif