#include <assert.h>
#include <string.h>
#include "Proofs/MiniPoW/miniPoWSolve.h"

static void test_init_get_set(void) {
    mini_pow_solve_t s;
    memset(&s, 0xAA, sizeof(s));

    mini_pow_solve_init(&s);
    assert(s.nonce == 0);
    assert(s.complexity == 0);
    assert(s.challenge_id == 0);
    for (size_t i = 0; i < sizeof(s.reserved); ++i) assert(s.reserved[i] == 0);

    mini_pow_solve_set_nonce(&s, 0x1122334455667788ULL);
    mini_pow_solve_set_complexity(&s, 5);
    mini_pow_solve_set_challenge_id(&s, 7);

    assert(*mini_pow_solve_get_nonce(&s) == 0x1122334455667788ULL);
    assert(mini_pow_solve_get_complexity(&s) == 5);
    assert(mini_pow_solve_get_challenge_id(&s) == 7);
}

static void test_serialize_deserialize(void) {
    mini_pow_solve_t s, t;
    uint8_t buf[MINI_POW_SOLVE_SIZE];

    mini_pow_solve_init(&s);
    s.nonce = 0x0102030405060708ULL;
    s.complexity = 9;
    s.challenge_id = 3;

    assert(mini_pow_solve_serialize(&s, buf, MINI_POW_SOLVE_SIZE) == OP_SUCCESS);
    assert(buf[0] == 0x01 && buf[1] == 0x02 && buf[2] == 0x03 && buf[3] == 0x04);
    assert(buf[4] == 0x05 && buf[5] == 0x06 && buf[6] == 0x07 && buf[7] == 0x08);
    assert(buf[8] == 9);
    assert(buf[9] == 3);

    assert(mini_pow_solve_serialize(&s, buf, MINI_POW_SOLVE_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(mini_pow_solve_serialize(NULL, buf, MINI_POW_SOLVE_SIZE) == OP_NULL_PTR);
    assert(mini_pow_solve_serialize(&s, NULL, MINI_POW_SOLVE_SIZE) == OP_NULL_PTR);

    memset(&t, 0, sizeof(t));
    assert(mini_pow_solve_deserialize(&t, buf, MINI_POW_SOLVE_SIZE) == OP_SUCCESS);
    assert(t.nonce == s.nonce);
    assert(t.complexity == s.complexity);
    assert(t.challenge_id == s.challenge_id);

    assert(mini_pow_solve_deserialize(&t, buf, MINI_POW_SOLVE_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(mini_pow_solve_deserialize(NULL, buf, MINI_POW_SOLVE_SIZE) == OP_NULL_PTR);
    assert(mini_pow_solve_deserialize(&t, NULL, MINI_POW_SOLVE_SIZE) == OP_NULL_PTR);

    buf[0] = 0xDE;
    buf[1] = 0xAD;
    buf[2] = 0xBE;
    buf[3] = 0xEF;
    buf[4] = 0xFE;
    buf[5] = 0xED;
    buf[6] = 0xBA;
    buf[7] = 0xBE;
    buf[8] = 1;
    buf[9] = 2;
    assert(mini_pow_solve_deserialize(&t, buf, MINI_POW_SOLVE_SIZE) == OP_SUCCESS);
    assert(t.nonce == 0xDEADBEEFFEEDBABEULL);
    assert(t.complexity == 1);
    assert(t.challenge_id == 2);
}

static void test_check_complexity_met(void) {
    uint256 h;
    uint256_zero(&h);

    h.w[0] = 0x4000000000000000ULL; // leading_zeros = 1
    assert(check_complexity_met(&h, 0) == true);
    assert(check_complexity_met(&h, 1) == false);

    h.w[0] = 0x2000000000000000ULL; // leading_zeros = 2
    assert(check_complexity_met(&h, 1) == true);

    h.w[0] = 0;
    h.w[1] = 0x8000000000000000ULL; // leading_zeros = 64
    assert(check_complexity_met(&h, 63) == true);
    assert(check_complexity_met(&h, 64) == false);
}

static void test_solve_challenge(void) {
    mini_pow_challenge_t ch;
    mini_pow_solve_t sol;
    mini_pow_solve_t *sol_ptr = &sol;

    mini_pow_challenge_init(&ch);
    ch.challenge_id = 5;
    ch.complexity = 0;
    ch.challenge.w[0] = 0x0102030405060708ULL;
    ch.challenge.w[1] = 0x1112131415161718ULL;
    ch.challenge.w[2] = 0x2122232425262728ULL;
    ch.challenge.w[3] = 0x3132333435363738ULL;

    mini_pow_solve_init(&sol);
    mini_pow_solve_solve_challenge(&ch, &sol_ptr);
    assert(sol_ptr != NULL);
    assert(sol.challenge_id == ch.challenge_id);
    assert(sol.complexity == ch.complexity);

    uint256 hash;
    uint8_t buf[UINT64_SIZE];
    uint8_t buf512[UINT512_SIZE];
    uint512 concat;

    assert(uint64_t_serialize(sol.nonce, buf, UINT64_SIZE) == OP_SUCCESS);
    hash256_buffer(buf, UINT64_SIZE, &hash);
    uint512_from_two_uint256(&concat, &ch.challenge, &hash);
    assert(uint512_serialize(&concat, buf512, UINT512_SIZE) == OP_SUCCESS);
    hash256_buffer(buf512, UINT512_SIZE, &hash);
    assert(check_complexity_met(&hash, ch.complexity));
}

int main(void) {
    test_init_get_set();
    test_serialize_deserialize();
    test_check_complexity_met();
    test_solve_challenge();
    return 0;
}
