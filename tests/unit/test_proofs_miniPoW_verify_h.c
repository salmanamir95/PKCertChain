#include <assert.h>
#include "Proofs/MiniPoW/miniPoWVerify.h"

static void test_is_valid_challenge(void) {
    mini_pow_challenge_t ch;
    mini_pow_solve_t sol;
    mini_pow_solve_t *sol_ptr = &sol;

    mini_pow_challenge_init(&ch);
    ch.challenge_id = 2;
    ch.complexity = 0;
    ch.challenge.w[0] = 0xDEADBEEFCAFEBABEULL;
    ch.challenge.w[1] = 0x1111111111111111ULL;
    ch.challenge.w[2] = 0x2222222222222222ULL;
    ch.challenge.w[3] = 0x3333333333333333ULL;

    mini_pow_solve_init(&sol);
    mini_pow_solve_solve_challenge(&ch, &sol_ptr);
    assert(sol_ptr != NULL);

    assert(isValidChallenge(&ch, &sol) == true);

    sol.challenge_id = (uint8_t)(ch.challenge_id + 1);
    assert(isValidChallenge(&ch, &sol) == false);

    sol.challenge_id = ch.challenge_id;
    ch.complexity = 1;
    assert(isValidChallenge(&ch, &sol) == false);

    assert(isValidChallenge(NULL, &sol) == false);
    assert(isValidChallenge(&ch, NULL) == false);
}

int main(void) {
    test_is_valid_challenge();
    return 0;
}
