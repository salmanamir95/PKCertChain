#include <assert.h>
#include <string.h>
#include "blockchain/certificate.h"

static void test_init_get_set(void) {
    certificate c;
    memset(&c, 0xAA, sizeof(c));

    cert_init(&c);
    for (int i = 0; i < 4; ++i) {
        assert(c.pubSignKey.w[i] == 0);
        assert(c.pubEncKey.w[i] == 0);
    }
    assert(c.id == 0);
    for (size_t i = 0; i < sizeof(c.reserved); ++i) assert(c.reserved[i] == 0);

    uint256 s, e;
    s.w[0] = 0x0102030405060708ULL;
    s.w[1] = 0x1112131415161718ULL;
    s.w[2] = 0x2122232425262728ULL;
    s.w[3] = 0x3132333435363738ULL;
    e.w[0] = 0x4142434445464748ULL;
    e.w[1] = 0x5152535455565758ULL;
    e.w[2] = 0x6162636465666768ULL;
    e.w[3] = 0x7172737475767778ULL;

    cert_set_pubSignKey(&c, &s);
    cert_set_pubEncKey(&c, &e);
    cert_set_id(&c, 9);

    assert(uint256_equal(cert_get_pubSignKey_ptr(&c), &s));
    assert(uint256_equal(cert_get_pubEncKey(&c), &e));
    assert(cert_get_id(&c) == 9);
}

static void test_copy(void) {
    certificate src, dst;
    cert_init(&src);
    cert_init(&dst);

    src.pubSignKey.w[0] = 0xAAAAAAAAAAAAAAAAULL;
    src.pubEncKey.w[0] = 0xBBBBBBBBBBBBBBBBULL;
    src.id = 7;

    memset(&dst, 0xCC, sizeof(dst));
    cert_copy(&dst, &src);

    assert(uint256_equal(&dst.pubSignKey, &src.pubSignKey));
    assert(uint256_equal(&dst.pubEncKey, &src.pubEncKey));
    assert(dst.id == src.id);
    for (size_t i = 0; i < sizeof(dst.reserved); ++i) assert(dst.reserved[i] == 0);
}

static void test_serialize_deserialize(void) {
    certificate src, dst;
    uint8_t buf[CERT_SIZE];

    cert_init(&src);
    src.pubSignKey.w[0] = 0x0102030405060708ULL;
    src.pubEncKey.w[0] = 0x1112131415161718ULL;
    src.id = 4;

    assert(cert_serialize(&src, buf, CERT_SIZE) == OP_SUCCESS);
    assert(buf[0] == 0x01 && buf[1] == 0x02 && buf[2] == 0x03 && buf[3] == 0x04);
    assert(buf[32] == 0x11 && buf[33] == 0x12 && buf[34] == 0x13 && buf[35] == 0x14);
    assert(buf[CERT_SIZE - 1] == 4);

    assert(cert_serialize(&src, buf, CERT_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(cert_serialize(NULL, buf, CERT_SIZE) == OP_NULL_PTR);
    assert(cert_serialize(&src, NULL, CERT_SIZE) == OP_NULL_PTR);

    memset(&dst, 0, sizeof(dst));
    assert(cert_deserialize(&dst, buf, CERT_SIZE) == OP_SUCCESS);
    assert(uint256_equal(&dst.pubSignKey, &src.pubSignKey));
    assert(uint256_equal(&dst.pubEncKey, &src.pubEncKey));
    assert(dst.id == src.id);

    assert(cert_deserialize(&dst, buf, CERT_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(cert_deserialize(NULL, buf, CERT_SIZE) == OP_NULL_PTR);
    assert(cert_deserialize(&dst, NULL, CERT_SIZE) == OP_NULL_PTR);
}

int main(void) {
    test_init_get_set();
    test_copy();
    test_serialize_deserialize();
    return 0;
}
