#ifndef PKCERTCHAIN_H
#define PKCERTCHAIN_H

#include "pkcertchain_config.h"



#ifndef PKCERTCHAIN_INLINE
#define PKCERTCHAIN_INLINE static inline __attribute__((always_inline))
#endif

#include <math.h>
#include <stdint.h>
#include <string.h>
#include "blockchain/block.h"
#include "util/SignUtils.h"
#include "util/EncUtils.h"
#include "Proofs/MiniPoW/miniPoWChallenge.h"
#include "Proofs/MiniPoW/miniPoWSolve.h"
#include "Proofs/MiniPoW/miniPoWVerify.h"
#include "Proofs/MiniPoW/miniPoWSession.h"
#include "Proofs/MiniPoW/miniPoWQueue.h"

typedef struct __attribute__((aligned(4))) {
    block blocks[100]; //148
    uint32_t index;
    char NetworkName[64];
    uint8_t complexity;
    uint64_t next_challenge_id;
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
    chain->complexity = 1;
    memset(chain->NetworkName, 0, sizeof(chain->NetworkName));
    chain->next_challenge_id = 1;
    return OP_SUCCESS;
}

PKCERTCHAIN_INLINE uint64_t generate_challenge_id(PKCertChain *chain)
{
    if (!chain) return 0;
    return chain->next_challenge_id++;
}

/*
 * Step 4 (pre-check): verify previous block integrity.
 */
PKCERTCHAIN_INLINE OpStatus_t verify_prev_block(const PKCertChain *chain)
{
    if (!chain) return OP_NULL_PTR;
    if (chain->index == 0) return OP_INVALID_STATE;

    const block *prev = &chain->blocks[chain->index - 1];

    uint256 prev_cert_hash;
    if (hash_certificate(&prev->cert, &prev_cert_hash) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (!uint256_equal(&prev_cert_hash, &prev->CurrentCertHash)) return OP_INVALID_INPUT;

    uint8_t cert_buf[CERT_SIZE];
    if (cert_serialize(&prev->cert, cert_buf, sizeof(cert_buf)) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (!verify_buffer_ed25519(cert_buf, sizeof(cert_buf), &prev->cert.pubSignKey, &prev->SignedByVerifier))
        return OP_INVALID_INPUT;

    return OP_SUCCESS;
}

/*
 * Step 1: give MiniPoW challenge for a candidate block.
 */
PKCERTCHAIN_INLINE OpStatus_t give_mini_pow_challenge(const PKCertChain *chain,
                                                      const block *candidate,
                                                      uint8_t complexity,
                                                      uint64_t challenge_id,
                                                      uint64_t issued_time_seconds,
                                                      mini_pow_session_t *out_session)
{
    if (!chain || !candidate || !out_session) return OP_NULL_PTR;

    OpStatus_t st = verify_prev_block(chain);
    if (st != OP_SUCCESS) return st;

    mini_pow_challenge_init(&out_session->challenge);
    st = generate_mini_pow_Challenge((block *)candidate, complexity, &out_session->challenge);
    if (st != OP_SUCCESS) return st;

    out_session->challenge.challenge_id = challenge_id;
    out_session->issued_time_seconds = issued_time_seconds;
    out_session->received_time_seconds = 0;
    out_session->target_index = chain->index;
    return OP_SUCCESS;
}

PKCERTCHAIN_INLINE OpStatus_t give_mini_pow_challenge_auto(PKCertChain *chain,
                                                           const block *candidate,
                                                           uint64_t issued_time_seconds,
                                                           mini_pow_session_t *out_session)
{
    if (!chain) return OP_NULL_PTR;
    uint64_t challenge_id = generate_challenge_id(chain);
    return give_mini_pow_challenge(chain, candidate, chain->complexity, challenge_id,
                                   issued_time_seconds, out_session);
}

/*
 * Step 2: verify MiniPoW solution against a challenge.
 */
PKCERTCHAIN_INLINE bool verify_mini_pow_solution(const mini_pow_session_t *session,
                                                 const mini_pow_solve_t *solve,
                                                 uint64_t received_time_seconds,
                                                 uint64_t *out_elapsed_seconds)
{
    if (!session || !solve) return false;
    if (!isValidChallenge(&session->challenge, solve)) return false;

    if (received_time_seconds < session->issued_time_seconds) return false;
    if (out_elapsed_seconds) {
        *out_elapsed_seconds = received_time_seconds - session->issued_time_seconds;
    }
    return true;
}

/*
 * Step 3: add block if PoW solution is valid.
 */
PKCERTCHAIN_INLINE uint8_t clamp_complexity(int value)
{
    if (value < 1) return 1;
    if (value > 220) return 220;
    return (uint8_t)value;
}

PKCERTCHAIN_INLINE uint8_t update_complexity(uint8_t current, uint64_t elapsed_seconds)
{
    double elapsed_min = (double)elapsed_seconds / 60.0;
    double new_complexity = (double)current;

    if (elapsed_min < 5.0) {
        double val = (5.0 - elapsed_min) / 5.0 * (double)current;
        new_complexity = new_complexity + 0.6 * val;
    } else if (elapsed_min > 5.0) {
        double val = (elapsed_min - 5.0) / 5.0 * elapsed_min;
        new_complexity = new_complexity - 0.6 * val;
    }

    return clamp_complexity((int)floor(new_complexity));
}

PKCERTCHAIN_INLINE OpStatus_t add_block_if_pow(const PKCertChain *chain,
                                               const mini_pow_session_t *session,
                                               const mini_pow_solve_t *solve,
                                               const block *candidate,
                                               uint64_t received_time_seconds,
                                               PKCertChain *out_chain)
{
    if (!chain || !session || !solve || !candidate || !out_chain) return OP_NULL_PTR;
    if (chain->index == 0) return OP_INVALID_STATE;
    if (chain->index >= 100) return OP_INVALID_INPUT;

    uint64_t elapsed_seconds = 0;
    if (!verify_mini_pow_solution(session, solve, received_time_seconds, &elapsed_seconds))
        return OP_INVALID_INPUT;

    if (session->target_index != chain->index) return OP_INVALID_STATE;

    *out_chain = *chain;
    block_copy(&out_chain->blocks[out_chain->index], candidate);
    out_chain->index += 1;
    out_chain->complexity = update_complexity(out_chain->complexity, elapsed_seconds);
    return OP_SUCCESS;
}

PKCERTCHAIN_INLINE OpStatus_t give_mini_pow_challenge_enqueue(PKCertChain *chain,
                                                              mini_pow_queue_t *queue,
                                                              const block *candidate,
                                                              uint64_t issued_time_seconds,
                                                              mini_pow_session_t *out_session)
{
    if (!chain || !queue || !candidate || !out_session) return OP_NULL_PTR;

    OpStatus_t st = give_mini_pow_challenge_auto(chain, candidate, issued_time_seconds, out_session);
    if (st != OP_SUCCESS) return st;

    return mini_pow_queue_add(queue, out_session, candidate);
}

PKCERTCHAIN_INLINE OpStatus_t add_block_from_queue(PKCertChain *chain,
                                                   mini_pow_queue_t *queue,
                                                   const mini_pow_solve_t *solve,
                                                   uint64_t received_time_seconds)
{
    if (!chain || !queue || !solve) return OP_NULL_PTR;

    mini_pow_session_t session;
    block candidate;
    OpStatus_t st = mini_pow_queue_take(queue, solve->challenge_id, &session, &candidate);
    if (st != OP_SUCCESS) return st;

    OpStatus_t st2 = add_block_if_pow(chain, &session, solve, &candidate, received_time_seconds, chain);
    if (st2 == OP_SUCCESS) {
        mini_pow_queue_prune_by_index(queue, session.target_index);
    }
    return st2;
}

#endif // PKCERTCHAIN_H
