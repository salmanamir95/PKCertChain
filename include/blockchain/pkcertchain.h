#ifndef PKCERTCHAIN_H
#define PKCERTCHAIN_H

#include "pkcertchain_config.h"



#ifndef PKCERTCHAIN_INLINE
#define PKCERTCHAIN_INLINE static inline __attribute__((always_inline))
#endif

#include <stdint.h>
#include "blockchain/block.h"
#include "util/SignUtils.h"
#include "util/EncUtils.h"

typedef struct __attribute__((aligned(4))) {
    block blocks[100]; //148
    uint32_t index;
} PKCertChain;

PKCERTCHAIN_INLINE OpStatus_t Gensis_Block(PKCertChain *chain)
{
    if (!chain) return OP_NULL_PTR;
    if (chain->index != 0) return OP_INVALID_STATE;

    block *genesis = &chain->blocks[0];
    block_init(genesis);

    uint256 sign_priv;
    uint256 sign_pub;
    uint256 enc_priv;
    uint256 enc_pub;

    if (GenerateSignKeys(&sign_priv, &sign_pub) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (GenerateEncKeys(&enc_priv, &enc_pub) != OP_SUCCESS) return OP_INVALID_INPUT;

    certificate cert;
    cert_init(&cert);
    cert_set_pubSignKey(&cert, &sign_pub);
    cert_set_pubEncKey(&cert, &enc_pub);
    cert_set_id(&cert, 1);

    uint512 sig;
    if (cert_sign(&cert, &sign_priv, &sig) != OP_SUCCESS) return OP_INVALID_INPUT;

    block_set_cert(genesis, &cert);
    block_set_signed_by_verifier(genesis, &sig);
    block_set_height(genesis, 0);
    block_set_timestamp(genesis, 0);

    uint256 cert_hash;
    if (hash_certificate(&cert, &cert_hash) != OP_SUCCESS) return OP_INVALID_INPUT;
    block_set_current_cert_hash(genesis, &cert_hash);

    // Genesis has no previous block
    uint256_zero(&genesis->prevHash);

    chain->index = 1;
    return OP_SUCCESS;
}

#endif // PKCERTCHAIN_H
