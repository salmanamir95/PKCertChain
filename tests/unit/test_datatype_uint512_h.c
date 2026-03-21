#include <assert.h>
#include <string.h>
#include "datatype/uint512.h"

static void test_zero_from_u64(void) {
    uint512 v;
    uint512_zero(&v);
    for (int i = 0; i < 8; ++i) assert(v.w[i] == 0);

    uint512_from_u64(&v, 0xDEADBEEFCAFEBABEULL);
    assert(v.w[0] == 0xDEADBEEFCAFEBABEULL);
    for (int i = 1; i < 8; ++i) assert(v.w[i] == 0);
}

static void test_equal_not_equal(void) {
    uint512 a, b;
    uint512_zero(&a);
    uint512_zero(&b);
    assert(uint512_equal(&a, &b));
    assert(!uint512_not_equal(&a, &b));

    b.w[7] = 1;
    assert(!uint512_equal(&a, &b));
    assert(uint512_not_equal(&a, &b));
}

static void test_bit_access(void) {
    uint512 v;
    uint512_zero(&v);
    assert(uint512_get_bit(&v, 0) == 0);
    assert(uint512_get_bit(&v, 511) == 0);
    assert(uint512_get_bit(&v, 63) == 0);
    assert(uint512_get_bit(&v, 64) == 0);

    uint512_set_bit(&v, 0, true);
    uint512_set_bit(&v, 63, true);
    uint512_set_bit(&v, 64, true);
    uint512_set_bit(&v, 511, true);
    assert(uint512_get_bit(&v, 0) == 1);
    assert(uint512_get_bit(&v, 63) == 1);
    assert(uint512_get_bit(&v, 64) == 1);
    assert(uint512_get_bit(&v, 511) == 1);

    uint512_set_bit(&v, 0, false);
    uint512_set_bit(&v, 63, false);
    uint512_set_bit(&v, 64, false);
    uint512_set_bit(&v, 511, false);
    assert(uint512_get_bit(&v, 0) == 0);
    assert(uint512_get_bit(&v, 63) == 0);
    assert(uint512_get_bit(&v, 64) == 0);
    assert(uint512_get_bit(&v, 511) == 0);
}

static void test_copy(void) {
    uint512 a, b;
    for (int i = 0; i < 8; ++i) a.w[i] = (uint64_t)(i + 1) * 0x0102030405060708ULL;
    uint512_copy(&b, &a);
    assert(memcmp(&a, &b, sizeof(uint512)) == 0);
}

static void test_serialize_deserialize(void) {
    uint512 a, b;
    uint8_t buf[UINT512_SIZE];

    for (int i = 0; i < 8; ++i) {
        a.w[i] = 0x0102030405060708ULL + (uint64_t)i;
    }

    assert(uint512_serialize(&a, buf, UINT512_SIZE) == OP_SUCCESS);
    assert(buf[0] == 0x01 && buf[1] == 0x02 && buf[2] == 0x03 && buf[3] == 0x04);
    assert(buf[4] == 0x05 && buf[5] == 0x06 && buf[6] == 0x07 && buf[7] == 0x08);

    assert(uint512_serialize(&a, buf, UINT512_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(uint512_serialize(NULL, buf, UINT512_SIZE) == OP_NULL_PTR);
    assert(uint512_serialize(&a, NULL, UINT512_SIZE) == OP_NULL_PTR);

    memset(&b, 0, sizeof(b));
    assert(uint512_deserialize(&b, buf, UINT512_SIZE) == OP_SUCCESS);
    assert(uint512_equal(&a, &b));

    assert(uint512_deserialize(&b, buf, UINT512_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(uint512_deserialize(NULL, buf, UINT512_SIZE) == OP_NULL_PTR);
    assert(uint512_deserialize(&b, NULL, UINT512_SIZE) == OP_NULL_PTR);

    for (int i = 0; i < 8; ++i) a.w[i] = 0xFFFFFFFFFFFFFFFFULL;
    assert(uint512_serialize(&a, buf, UINT512_SIZE) == OP_SUCCESS);
    memset(&b, 0, sizeof(b));
    assert(uint512_deserialize(&b, buf, UINT512_SIZE) == OP_SUCCESS);
    assert(uint512_equal(&a, &b));
}

static void test_from_two_uint256(void) {
    uint256 hi, lo;
    uint512 out;

    for (int i = 0; i < 4; ++i) {
        hi.w[i] = 0x1111111111111111ULL + (uint64_t)i;
        lo.w[i] = 0xAAAAAAAAAAAAAAAAULL + (uint64_t)i;
    }

    uint512_from_two_uint256(&out, &hi, &lo);
    assert(memcmp(out.w, hi.w, sizeof(uint256)) == 0);
    assert(memcmp(out.w + 4, lo.w, sizeof(uint256)) == 0);
}

int main(void) {
    test_zero_from_u64();
    test_equal_not_equal();
    test_bit_access();
    test_copy();
    test_serialize_deserialize();
    test_from_two_uint256();
    return 0;
}
