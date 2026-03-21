#include <assert.h>
#include <string.h>
#include "util/ser_primitives.h"

static void test_uint8(void) {
    uint8_t buf[1] = {0};
    uint8_t out = 0;

    assert(uint8_t_serialize(0xAB, buf, 1) == OP_SUCCESS);
    assert(buf[0] == 0xAB);
    assert(uint8_t_serialize(0xAB, buf, 0) == OP_BUF_TOO_SMALL);
    assert(uint8_t_serialize(0xAB, NULL, 1) == OP_NULL_PTR);

    assert(uint8_t_deserialize(&out, buf, 1) == OP_SUCCESS);
    assert(out == 0xAB);
    assert(uint8_t_deserialize(&out, buf, 0) == OP_BUF_TOO_SMALL);
    assert(uint8_t_deserialize(NULL, buf, 1) == OP_NULL_PTR);
    assert(uint8_t_deserialize(&out, NULL, 1) == OP_NULL_PTR);
}

static void test_uint16(void) {
    uint8_t buf[2] = {0};
    uint16_t out = 0;

    assert(uint16_t_serialize(0x1234, buf, 2) == OP_SUCCESS);
    assert(buf[0] == 0x12 && buf[1] == 0x34);
    assert(uint16_t_serialize(0x1234, buf, 1) == OP_BUF_TOO_SMALL);
    assert(uint16_t_serialize(0x1234, NULL, 2) == OP_NULL_PTR);

    assert(uint16_t_deserialize(&out, buf, 2) == OP_SUCCESS);
    assert(out == 0x1234);
    assert(uint16_t_deserialize(&out, buf, 1) == OP_BUF_TOO_SMALL);
    assert(uint16_t_deserialize(NULL, buf, 2) == OP_NULL_PTR);
    assert(uint16_t_deserialize(&out, NULL, 2) == OP_NULL_PTR);

    buf[0] = 0xBE;
    buf[1] = 0xEF;
    assert(uint16_t_deserialize(&out, buf, 2) == OP_SUCCESS);
    assert(out == 0xBEEF);
}

static void test_uint32(void) {
    uint8_t buf[4] = {0};
    uint32_t out = 0;

    assert(uint32_t_serialize(0x11223344u, buf, 4) == OP_SUCCESS);
    assert(buf[0] == 0x11 && buf[1] == 0x22 && buf[2] == 0x33 && buf[3] == 0x44);
    assert(uint32_t_serialize(0x11223344u, buf, 3) == OP_BUF_TOO_SMALL);
    assert(uint32_t_serialize(0x11223344u, NULL, 4) == OP_NULL_PTR);

    assert(uint32_t_deserialize(&out, buf, 4) == OP_SUCCESS);
    assert(out == 0x11223344u);
    assert(uint32_t_deserialize(&out, buf, 3) == OP_BUF_TOO_SMALL);
    assert(uint32_t_deserialize(NULL, buf, 4) == OP_NULL_PTR);
    assert(uint32_t_deserialize(&out, NULL, 4) == OP_NULL_PTR);

    buf[0] = 0xDE;
    buf[1] = 0xAD;
    buf[2] = 0xBE;
    buf[3] = 0xEF;
    assert(uint32_t_deserialize(&out, buf, 4) == OP_SUCCESS);
    assert(out == 0xDEADBEEFu);
}

static void test_uint64(void) {
    uint8_t buf[8] = {0};
    uint64_t out = 0;

    assert(uint64_t_serialize(0x0102030405060708ULL, buf, 8) == OP_SUCCESS);
    assert(buf[0] == 0x01 && buf[1] == 0x02 && buf[2] == 0x03 && buf[3] == 0x04 &&
           buf[4] == 0x05 && buf[5] == 0x06 && buf[6] == 0x07 && buf[7] == 0x08);
    assert(uint64_t_serialize(0x0102030405060708ULL, buf, 7) == OP_BUF_TOO_SMALL);
    assert(uint64_t_serialize(0x0102030405060708ULL, NULL, 8) == OP_NULL_PTR);

    assert(uint64_t_deserialize(&out, buf, 8) == OP_SUCCESS);
    assert(out == 0x0102030405060708ULL);
    assert(uint64_t_deserialize(&out, buf, 7) == OP_BUF_TOO_SMALL);
    assert(uint64_t_deserialize(NULL, buf, 8) == OP_NULL_PTR);
    assert(uint64_t_deserialize(&out, NULL, 8) == OP_NULL_PTR);

    buf[0] = 0xDE;
    buf[1] = 0xAD;
    buf[2] = 0xBE;
    buf[3] = 0xEF;
    buf[4] = 0xFE;
    buf[5] = 0xED;
    buf[6] = 0xBA;
    buf[7] = 0xBE;
    assert(uint64_t_deserialize(&out, buf, 8) == OP_SUCCESS);
    assert(out == 0xDEADBEEFFEEDBABEULL);
}

int main(void) {
    test_uint8();
    test_uint16();
    test_uint32();
    test_uint64();
    return 0;
}
