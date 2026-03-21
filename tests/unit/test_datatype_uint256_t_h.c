#include <assert.h>
#include <string.h>
#include "datatype/uint256_t.h"

static void test_zero_from_u64(void) {
    uint256 v;
    uint256_zero(&v);
    for (int i = 0; i < 4; ++i) assert(v.w[i] == 0);

    uint256_from_u64(&v, 0xAABBCCDDEEFF0011ULL);
    assert(v.w[0] == 0xAABBCCDDEEFF0011ULL);
    assert(v.w[1] == 0 && v.w[2] == 0 && v.w[3] == 0);
}

static void test_equal_not_equal(void) {
    uint256 a, b;
    uint256_zero(&a);
    uint256_zero(&b);
    assert(uint256_equal(&a, &b));
    assert(!uint256_not_equal(&a, &b));

    b.w[2] = 1;
    assert(!uint256_equal(&a, &b));
    assert(uint256_not_equal(&a, &b));
}

static void test_bit_access(void) {
    uint256 v;
    uint256_zero(&v);
    assert(uint256_get_bit(&v, 0) == 0);
    assert(uint256_get_bit(&v, 255) == 0);
    assert(uint256_get_bit(&v, 63) == 0);
    assert(uint256_get_bit(&v, 64) == 0);

    uint256_set_bit(&v, 0, true);
    uint256_set_bit(&v, 63, true);
    uint256_set_bit(&v, 64, true);
    uint256_set_bit(&v, 255, true);
    assert(uint256_get_bit(&v, 0) == 1);
    assert(uint256_get_bit(&v, 63) == 1);
    assert(uint256_get_bit(&v, 64) == 1);
    assert(uint256_get_bit(&v, 255) == 1);

    uint256_set_bit(&v, 0, false);
    uint256_set_bit(&v, 63, false);
    uint256_set_bit(&v, 64, false);
    uint256_set_bit(&v, 255, false);
    assert(uint256_get_bit(&v, 0) == 0);
    assert(uint256_get_bit(&v, 63) == 0);
    assert(uint256_get_bit(&v, 64) == 0);
    assert(uint256_get_bit(&v, 255) == 0);
}

static void test_copy(void) {
    uint256 a, b;
    for (int i = 0; i < 4; ++i) a.w[i] = (uint64_t)(i + 1) * 0x1111111111111111ULL;
    uint256_copy(&b, &a);
    assert(memcmp(&a, &b, sizeof(uint256)) == 0);
}

static void test_serialize_deserialize(void) {
    uint256 a, b;
    uint8_t buf[UINT256_SIZE];

    a.w[0] = 0x0102030405060708ULL;
    a.w[1] = 0x1112131415161718ULL;
    a.w[2] = 0x2122232425262728ULL;
    a.w[3] = 0x3132333435363738ULL;

    assert(uint256_serialize(&a, buf, UINT256_SIZE) == OP_SUCCESS);
    assert(buf[0] == 0x01 && buf[1] == 0x02 && buf[2] == 0x03 && buf[3] == 0x04);
    assert(buf[4] == 0x05 && buf[5] == 0x06 && buf[6] == 0x07 && buf[7] == 0x08);
    assert(buf[8] == 0x11 && buf[9] == 0x12);

    assert(uint256_serialize(&a, buf, UINT256_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(uint256_serialize(NULL, buf, UINT256_SIZE) == OP_NULL_PTR);
    assert(uint256_serialize(&a, NULL, UINT256_SIZE) == OP_NULL_PTR);

    memset(&b, 0, sizeof(b));
    assert(uint256_deserialize(&b, buf, UINT256_SIZE) == OP_SUCCESS);
    assert(uint256_equal(&a, &b));

    for (int i = 0; i < 4; ++i) a.w[i] = 0xFFFFFFFFFFFFFFFFULL;
    assert(uint256_serialize(&a, buf, UINT256_SIZE) == OP_SUCCESS);
    memset(&b, 0, sizeof(b));
    assert(uint256_deserialize(&b, buf, UINT256_SIZE) == OP_SUCCESS);
    assert(uint256_equal(&a, &b));

    assert(uint256_deserialize(&b, buf, UINT256_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(uint256_deserialize(NULL, buf, UINT256_SIZE) == OP_NULL_PTR);
    assert(uint256_deserialize(&b, NULL, UINT256_SIZE) == OP_NULL_PTR);
}

int main(void) {
    test_zero_from_u64();
    test_equal_not_equal();
    test_bit_access();
    test_copy();
    test_serialize_deserialize();
    return 0;
}
