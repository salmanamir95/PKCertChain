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
#include "Proofs/TierPoW/tierPoWChallenge.h"
#include "Proofs/TierPoW/tierPoWSolve.h"
#include "Proofs/TierPoW/tierPoWVerify.h"
#include "Proofs/TierPoW/tierPoWSession.h"
#include "Proofs/TierPoW/tierPoWQueue.h"

typedef struct __attribute__((aligned(4))) {
    block blocks[100]; //148
    uint32_t index;
    char NetworkName[64];
    uint8_t complexity;
    uint64_t next_challenge_id;
    double avg_solve_time_seconds;
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

    if (GenerateSignKeys(&sign_priv, &sign_pub, chain->NetworkName) != OP_SUCCESS) return OP_INVALID_INPUT;
    if (GenerateEncKeys(&enc_priv, &enc_pub, chain->NetworkName) != OP_SUCCESS) return OP_INVALID_INPUT;

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
    chain->avg_solve_time_seconds = 600.0;
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

PKCERTCHAIN_INLINE OpStatus_t validate_before_send_mini_pow(const PKCertChain *chain,
                                                            const block *candidate)
{
    if (!chain || !candidate) return OP_NULL_PTR;
    if (chain->index == 0) return OP_INVALID_STATE;
    if (chain->index >= 100) return OP_INVALID_INPUT;
    return verify_prev_block(chain);
}

PKCERTCHAIN_INLINE OpStatus_t validate_before_solve_mini_pow(const mini_pow_session_t *session)
{
    if (!session) return OP_NULL_PTR;
    if (session->challenge.complexity == 0) return OP_INVALID_INPUT;
    if (session->challenge.challenge_id == 0) return OP_INVALID_INPUT;
    return OP_SUCCESS;
}

PKCERTCHAIN_INLINE OpStatus_t validate_before_verify_mini_pow(const mini_pow_session_t *session,
                                                              const mini_pow_solve_t *solve,
                                                              uint64_t received_time_seconds)
{
    if (!session || !solve) return OP_NULL_PTR;
    if (solve->challenge_id != session->challenge.challenge_id) return OP_INVALID_INPUT;
    if (received_time_seconds < session->issued_time_seconds) return OP_INVALID_INPUT;
    return OP_SUCCESS;
}

PKCERTCHAIN_INLINE OpStatus_t validate_before_assign_tier(const PKCertChain *chain,
                                                          uint64_t elapsed_seconds)
{
    if (!chain) return OP_NULL_PTR;
    if (elapsed_seconds == 0) return OP_INVALID_INPUT;
    if (chain->avg_solve_time_seconds <= 0.0) return OP_INVALID_INPUT;
    return OP_SUCCESS;
}

PKCERTCHAIN_INLINE OpStatus_t validate_before_send_tier_pow(const PKCertChain *chain,
                                                            const block *candidate,
                                                            Tier_t tier)
{
    if (!chain || !candidate) return OP_NULL_PTR;
    if (tier == TIER_INVALID) return OP_INVALID_INPUT;
    if (chain->index == 0) return OP_INVALID_STATE;
    if (chain->index >= 100) return OP_INVALID_INPUT;
    return verify_prev_block(chain);
}

PKCERTCHAIN_INLINE OpStatus_t validate_before_solve_tier_pow(const tier_pow_session_t *session)
{
    if (!session) return OP_NULL_PTR;
    if (session->challenge.complexity == 0) return OP_INVALID_INPUT;
    if (session->challenge.challenge_id == 0) return OP_INVALID_INPUT;
    return OP_SUCCESS;
}

PKCERTCHAIN_INLINE OpStatus_t validate_before_verify_tier_pow(const tier_pow_session_t *session,
                                                              const tier_pow_solve_t *solve,
                                                              uint64_t received_time_seconds)
{
    if (!session || !solve) return OP_NULL_PTR;
    if (solve->challenge_id != session->challenge.challenge_id) return OP_INVALID_INPUT;
    if (received_time_seconds < session->issued_time_seconds) return OP_INVALID_INPUT;
    return OP_SUCCESS;
}

PKCERTCHAIN_INLINE OpStatus_t validate_before_add_block(const PKCertChain *chain,
                                                        const block *candidate,
                                                        const tier_pow_session_t *session,
                                                        const tier_pow_solve_t *solve)
{
    if (!chain || !candidate || !session || !solve) return OP_NULL_PTR;
    if (chain->index == 0) return OP_INVALID_STATE;
    if (chain->index >= 100) return OP_INVALID_INPUT;
    if (session->target_index != chain->index) return OP_INVALID_STATE;
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

    OpStatus_t pre = validate_before_send_mini_pow(chain, candidate);
    if (pre != OP_SUCCESS) return pre;

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

PKCERTCHAIN_INLINE OpStatus_t give_tier_pow_challenge(const PKCertChain *chain,
                                                      const block *candidate,
                                                      uint8_t complexity,
                                                      uint64_t challenge_id,
                                                      uint64_t issued_time_seconds,
                                                      tier_pow_session_t *out_session)
{
    if (!chain || !candidate || !out_session) return OP_NULL_PTR;

    OpStatus_t pre = validate_before_send_tier_pow(chain, candidate, candidate->tier);
    if (pre != OP_SUCCESS) return pre;

    OpStatus_t st = verify_prev_block(chain);
    if (st != OP_SUCCESS) return st;

    tier_pow_challenge_init(&out_session->challenge);
    st = generate_tier_pow_challenge((block *)candidate, complexity, &out_session->challenge);
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
    if (validate_before_verify_mini_pow(session, solve, received_time_seconds) != OP_SUCCESS)
        return false;
    if (!isValidChallenge(&session->challenge, solve)) return false;

    if (received_time_seconds < session->issued_time_seconds) return false;
    if (out_elapsed_seconds) {
        *out_elapsed_seconds = received_time_seconds - session->issued_time_seconds;
    }
    return true;
}

PKCERTCHAIN_INLINE bool verify_tier_pow_solution(const tier_pow_session_t *session,
                                                 const tier_pow_solve_t *solve,
                                                 uint64_t received_time_seconds,
                                                 uint64_t *out_elapsed_seconds)
{
    if (!session || !solve) return false;
    if (validate_before_verify_tier_pow(session, solve, received_time_seconds) != OP_SUCCESS)
        return false;
    if (!isValidTierChallenge(&session->challenge, solve)) return false;

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

    if (elapsed_min < 10.0) {
        double val = (10.0 - elapsed_min) / 10.0 * (double)current;
        new_complexity = new_complexity + 0.6 * val;
    } else if (elapsed_min > 10.0) {
        double val = (elapsed_min - 10.0) / 10.0 * elapsed_min;
        new_complexity = new_complexity - 0.6 * val;
    }

    return clamp_complexity((int)floor(new_complexity));
}

PKCERTCHAIN_INLINE Tier_t classify_tier(double avg_seconds, uint64_t elapsed_seconds)
{
    if (avg_seconds <= 0.0) return TIER_INVALID;
    double elapsed = (double)elapsed_seconds;

    if (elapsed <= 0.25 * avg_seconds) return TIER_SERVER;
    if (elapsed <= 0.60 * avg_seconds) return TIER_DESKTOP;
    if (elapsed <= 1.50 * avg_seconds) return TIER_EDGE;
    if (elapsed <= 3.00 * avg_seconds) return TIER_MCU;
    return TIER_INVALID;
}

PKCERTCHAIN_INLINE double update_avg_solve_time(double prev_avg, uint64_t elapsed_seconds)
{
    const double alpha = 0.2;
    double elapsed = (double)elapsed_seconds;
    if (prev_avg <= 0.0) return elapsed;
    return (alpha * elapsed) + ((1.0 - alpha) * prev_avg);
}

PKCERTCHAIN_INLINE uint8_t tier_to_complexity(Tier_t tier, uint8_t base_complexity)
{
    uint8_t delta = (uint8_t)(base_complexity / 4);
    switch (tier) {
        case TIER_SERVER:  return (uint8_t)(50 + delta);
        case TIER_DESKTOP: return (uint8_t)(35 + delta);
        case TIER_EDGE:    return (uint8_t)(25 + delta);
        case TIER_MCU:     return (uint8_t)(20 + delta);
        default:           return 0;
    }
}

PKCERTCHAIN_INLINE Tier_t classify_tier_for_elapsed(const PKCertChain *chain, uint64_t elapsed_seconds)
{
    if (!chain) return TIER_INVALID;
    return classify_tier(chain->avg_solve_time_seconds, elapsed_seconds);
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
    out_chain->avg_solve_time_seconds = update_avg_solve_time(out_chain->avg_solve_time_seconds, elapsed_seconds);
    block_set_tier(&out_chain->blocks[out_chain->index],
                   classify_tier(out_chain->avg_solve_time_seconds, elapsed_seconds));
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

PKCERTCHAIN_INLINE OpStatus_t give_tier_pow_challenge_enqueue(PKCertChain *chain,
                                                              tier_pow_queue_t *queue,
                                                              const block *candidate,
                                                              uint8_t complexity,
                                                              uint64_t issued_time_seconds,
                                                              tier_pow_session_t *out_session)
{
    if (!chain || !queue || !candidate || !out_session) return OP_NULL_PTR;

    OpStatus_t pre = validate_before_send_tier_pow(chain, candidate, candidate->tier);
    if (pre != OP_SUCCESS) return pre;

    uint64_t challenge_id = generate_challenge_id(chain);
    OpStatus_t st = give_tier_pow_challenge(chain, candidate, complexity,
                                            challenge_id, issued_time_seconds, out_session);
    if (st != OP_SUCCESS) return st;

    return tier_pow_queue_add(queue, out_session, candidate);
}

PKCERTCHAIN_INLINE OpStatus_t add_block_from_tier_queue(PKCertChain *chain,
                                                        tier_pow_queue_t *queue,
                                                        const tier_pow_solve_t *solve,
                                                        uint64_t received_time_seconds)
{
    if (!chain || !queue || !solve) return OP_NULL_PTR;

    tier_pow_session_t session;
    block candidate;
    OpStatus_t st = tier_pow_queue_take(queue, solve->challenge_id, &session, &candidate);
    if (st != OP_SUCCESS) return st;

    if (validate_before_add_block(chain, &candidate, &session, solve) != OP_SUCCESS)
        return OP_INVALID_INPUT;

    uint64_t elapsed_seconds = 0;
    if (!verify_tier_pow_solution(&session, solve, received_time_seconds, &elapsed_seconds))
        return OP_INVALID_INPUT;

    block_copy(&chain->blocks[chain->index], &candidate);
    chain->avg_solve_time_seconds = update_avg_solve_time(chain->avg_solve_time_seconds, elapsed_seconds);
    chain->index += 1;
    chain->complexity = update_complexity(chain->complexity, elapsed_seconds);

    tier_pow_queue_prune_by_index(queue, session.target_index);
    return OP_SUCCESS;
}

// Note: blocks are only added from TierPoW queue (see add_block_from_tier_queue).

/*
 * Full flow: classify tier using MiniPoW, then run tier-based PoW, then add block.
 */
PKCERTCHAIN_INLINE OpStatus_t add_block_tiered_pow(PKCertChain *chain,
                                                   const block *candidate,
                                                   const mini_pow_solve_t *solve_classify,
                                                   uint64_t classify_issued_time,
                                                   uint64_t classify_received_time,
                                                   const tier_pow_solve_t *solve_tier,
                                                   uint64_t tier_issued_time,
                                                   uint64_t tier_received_time,
                                                   PKCertChain *out_chain)
{
    if (!chain || !candidate || !solve_classify || !solve_tier || !out_chain) return OP_NULL_PTR;

    // Step 0: verify previous block
    OpStatus_t st = verify_prev_block(chain);
    if (st != OP_SUCCESS) return st;

    // Step 1: classification challenge
    mini_pow_session_t classify_session;
    st = give_mini_pow_challenge(chain, candidate, chain->complexity,
                                 solve_classify->challenge_id,
                                 classify_issued_time, &classify_session);
    if (st != OP_SUCCESS) return st;

    uint64_t classify_elapsed = 0;
    if (!verify_mini_pow_solution(&classify_session, solve_classify,
                                  classify_received_time, &classify_elapsed)) {
        return OP_INVALID_INPUT;
    }

    // Step 2: classify tier (adaptive)
    if (validate_before_assign_tier(chain, classify_elapsed) != OP_SUCCESS) return OP_INVALID_INPUT;
    Tier_t tier = classify_tier_for_elapsed(chain, classify_elapsed);
    if (tier == TIER_INVALID) return OP_INVALID_INPUT;

    // Step 3: tier-based PoW challenge
    uint8_t tier_complexity = tier_to_complexity(tier, chain->complexity);
    if (tier_complexity == 0) return OP_INVALID_INPUT;

    block candidate_tier = *candidate;
    block_set_tier(&candidate_tier, tier);

    tier_pow_session_t tier_session;
    st = give_tier_pow_challenge(chain, &candidate_tier, tier_complexity,
                                 solve_tier->challenge_id,
                                 tier_issued_time, &tier_session);
    if (st != OP_SUCCESS) return st;

    // Step 4: verify tier PoW and add block
    uint64_t tier_elapsed = 0;
    if (!verify_tier_pow_solution(&tier_session, solve_tier, tier_received_time, &tier_elapsed))
        return OP_INVALID_INPUT;

    if (validate_before_add_block(chain, &candidate_tier, &tier_session, solve_tier) != OP_SUCCESS)
        return OP_INVALID_INPUT;

    *out_chain = *chain;
    block_copy(&out_chain->blocks[out_chain->index], &candidate_tier);
    out_chain->avg_solve_time_seconds = update_avg_solve_time(out_chain->avg_solve_time_seconds, tier_elapsed);
    block_set_tier(&out_chain->blocks[out_chain->index], tier);
    out_chain->index += 1;
    out_chain->complexity = update_complexity(out_chain->complexity, tier_elapsed);

    return OP_SUCCESS;
}

#endif // PKCERTCHAIN_H
