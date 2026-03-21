#include <assert.h>
#include <string.h>
#include "Proofs/MiniPoW/miniPoWChallenge.h"

static void test_init_get_set(void) {
    mini_pow_challenge_t pow;
    memset(&pow, 0xAA, sizeof(pow));
    pow.challenge_id = 0;

    mini_pow_challenge_init(&pow);
    for (int i = 0; i < 4; ++i) assert(pow.challenge.w[i] == 0);
    assert(pow.complexity == 0);
    for (size_t i = 0; i < sizeof(pow.reserved); ++i) assert(pow.reserved[i] == 0);

    uint256 ch;
    ch.w[0] = 0x0102030405060708ULL;
    ch.w[1] = 0x1112131415161718ULL;
    ch.w[2] = 0x2122232425262728ULL;
    ch.w[3] = 0x3132333435363738ULL;
    mini_pow_challenge_set_challenge(&pow, &ch);
    mini_pow_challenge_set_complexity(&pow, 7);
    mini_pow_challenge_set_challenge_id(&pow, 9);

    const uint256 *pch = mini_pow_challenge_get_challenge(&pow);
    assert(uint256_equal(pch, &ch));
    assert(mini_pow_challenge_get_complexity(&pow) == 7);
    assert(*mini_pow_challenge_get_challenge_id(&pow) == 9);
}

static void test_copy(void) {
    mini_pow_challenge_t src;
    mini_pow_challenge_t dst;
    memset(&src, 0, sizeof(src));
    memset(&dst, 0xBB, sizeof(dst));
    dst.challenge_id = 3;

    src.challenge.w[0] = 0xAAAABBBBCCCCDDDDULL;
    src.challenge.w[1] = 0x1111222233334444ULL;
    src.challenge.w[2] = 0x5555666677778888ULL;
    src.challenge.w[3] = 0x9999AAAABBBBCCCCULL;
    src.complexity = 4;
    src.challenge_id = 3;

    mini_pow_challenge_copy(&dst, &src);
    assert(uint256_equal(&dst.challenge, &src.challenge));
    assert(dst.complexity == src.complexity);
    for (size_t i = 0; i < sizeof(dst.reserved); ++i) assert(dst.reserved[i] == 0);
}

static void test_serialize_deserialize(void) {
    mini_pow_challenge_t src;
    mini_pow_challenge_t dst;
    uint8_t buf[MINI_POW_CHALLENGE_SIZE];

    src.challenge.w[0] = 0x0102030405060708ULL;
    src.challenge.w[1] = 0x1112131415161718ULL;
    src.challenge.w[2] = 0x2122232425262728ULL;
    src.challenge.w[3] = 0x3132333435363738ULL;
    src.complexity = 5;
    src.challenge_id = 6;

    assert(mini_pow_challenge_serialize(&src, buf, MINI_POW_CHALLENGE_SIZE) == OP_SUCCESS);
    assert(buf[0] == 0x01 && buf[1] == 0x02 && buf[2] == 0x03 && buf[3] == 0x04);
    assert(buf[32] == 5);
    assert(buf[33] == 6);

    assert(mini_pow_challenge_serialize(&src, buf, MINI_POW_CHALLENGE_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(mini_pow_challenge_serialize(NULL, buf, MINI_POW_CHALLENGE_SIZE) == OP_NULL_PTR);
    assert(mini_pow_challenge_serialize(&src, NULL, MINI_POW_CHALLENGE_SIZE) == OP_NULL_PTR);

    memset(&dst, 0, sizeof(dst));
    assert(mini_pow_challenge_deserialize(&dst, buf, MINI_POW_CHALLENGE_SIZE) == OP_SUCCESS);
    assert(uint256_equal(&dst.challenge, &src.challenge));
    assert(dst.complexity == src.complexity);
    assert(dst.challenge_id == src.challenge_id);

    assert(mini_pow_challenge_deserialize(&dst, buf, MINI_POW_CHALLENGE_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(mini_pow_challenge_deserialize(NULL, buf, MINI_POW_CHALLENGE_SIZE) == OP_NULL_PTR);
    assert(mini_pow_challenge_deserialize(&dst, NULL, MINI_POW_CHALLENGE_SIZE) == OP_NULL_PTR);
}

static void test_generate_mini_pow_challenge(void) {
    block blk;
    mini_pow_challenge_t pow;
    uint8_t buf[BLOCK_SIZE];
    uint256 expected;

    block_init(&blk);

    uint256 prev;
    prev.w[0] = 0x1111111111111111ULL;
    prev.w[1] = 0x2222222222222222ULL;
    prev.w[2] = 0x3333333333333333ULL;
    prev.w[3] = 0x4444444444444444ULL;
    block_set_prev_hash(&blk, &prev);
    block_set_height(&blk, 42);
    block_set_timestamp(&blk, 123456789ULL);

    certificate cert;
    cert_init(&cert);
    cert.id = 7;
    cert.pubSignKey.w[0] = 0xAAAAAAAAAAAAAAAAULL;
    cert.pubEncKey.w[0] = 0xBBBBBBBBBBBBBBBBULL;
    block_set_cert(&blk, &cert);

    assert(block_serialize(&blk, buf, BLOCK_SIZE) == OP_SUCCESS);
    hash256_buffer(buf, BLOCK_SIZE, &expected);

    assert(generate_mini_pow_Challenge(&blk, 9, &pow) == OP_SUCCESS);
    assert(uint256_equal(&pow.challenge, &expected));
    assert(pow.complexity == 9);
}

int main(void) {
    test_init_get_set();
    test_copy();
    test_serialize_deserialize();
    test_generate_mini_pow_challenge();
    return 0;
}
