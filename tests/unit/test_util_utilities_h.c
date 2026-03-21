#include <assert.h>
#include <string.h>
#include "util/utilities.h"

static void test_hash256_buffer(void) {
    const uint8_t msg[] = {'a', 'b', 'c'};
    const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint256 out;
    uint256_zero(&out);

    hash256_buffer(msg, sizeof(msg), &out);
    assert(memcmp(out.w, expected, sizeof(expected)) == 0);

    const uint8_t empty[] = {};
    const uint8_t expected_empty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    uint256_zero(&out);
    hash256_buffer(empty, 0, &out);
    assert(memcmp(out.w, expected_empty, sizeof(expected_empty)) == 0);
}

static void test_clz256(void) {
    uint256 v;
    uint256_zero(&v);
    assert(clz256(&v) == 256);

    uint256_zero(&v);
    v.w[0] = 0x8000000000000000ULL;
    assert(clz256(&v) == 0);

    uint256_zero(&v);
    v.w[1] = 0x0000000000000001ULL;
    assert(clz256(&v) == 127);

    uint256_zero(&v);
    v.w[3] = 0x0000000000000001ULL;
    assert(clz256(&v) == 255);
}

int main(void) {
    test_hash256_buffer();
    test_clz256();
    return 0;
}
