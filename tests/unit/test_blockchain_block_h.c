#include <assert.h>
#include <string.h>
#include "blockchain/block.h"

static void fill_block(block *blk) {
    certificate cert;
    cert_init(&cert);
    cert.id = 2;
    cert.pubSignKey.w[0] = 0x0102030405060708ULL;
    cert.pubEncKey.w[0] = 0x1112131415161718ULL;
    block_set_cert(blk, &cert);

    uint256 prev;
    prev.w[0] = 0xAAAAAAAABBBBBBBBULL;
    prev.w[1] = 0xCCCCCCCCDDDDDDDDULL;
    prev.w[2] = 0xEEEEEEEEFFFFFFFFULL;
    prev.w[3] = 0x1234567890ABCDEFULL;
    block_set_prev_hash(blk, &prev);

    block_set_height(blk, 99);
    block_set_timestamp(blk, 1234567890ULL);
}

static void test_init_get_set(void) {
    block blk;
    memset(&blk, 0xAA, sizeof(blk));

    block_init(&blk);
    assert(blk.timestamp == 0);

    fill_block(&blk);
    assert(block_get_timestamp(&blk) == 1234567890ULL);
    assert(*block_get_height(&blk) == 99);
    assert(uint256_equal(block_get_prev_hash(&blk), &blk.prevHash));
    assert(cert_get_id(block_get_cert_ptr(&blk)) == 2);
}

static void test_copy(void) {
    block a, b;
    block_init(&a);
    block_init(&b);
    fill_block(&a);

    memset(&b, 0xBB, sizeof(b));
    block_copy(&b, &a);

    assert(cert_get_id(block_get_cert_ptr(&b)) == cert_get_id(block_get_cert_ptr(&a)));
    assert(block_get_timestamp(&b) == block_get_timestamp(&a));
    assert(uint256_equal(block_get_prev_hash(&b), block_get_prev_hash(&a)));
    assert(*block_get_height(&b) == *block_get_height(&a));
}

static void test_serialize_deserialize(void) {
    block a, b;
    uint8_t buf[BLOCK_SIZE];

    block_init(&a);
    fill_block(&a);

    assert(block_serialize(&a, buf, BLOCK_SIZE) == OP_SUCCESS);
    assert(block_serialize(&a, buf, BLOCK_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(block_serialize(NULL, buf, BLOCK_SIZE) == OP_NULL_PTR);
    assert(block_serialize(&a, NULL, BLOCK_SIZE) == OP_NULL_PTR);

    // prevHash bytes at offset CERT_SIZE
    size_t off = CERT_SIZE;
    assert(buf[off + 0] == 0xAA && buf[off + 1] == 0xAA);
    // height at offset CERT_SIZE + UINT256_SIZE
    off = CERT_SIZE + UINT256_SIZE;
    assert(buf[off + 0] == 0x00 && buf[off + 7] == 0x63); // 99 in big-endian
    // timestamp at offset CERT_SIZE + UINT256_SIZE + UINT64_SIZE
    off = CERT_SIZE + UINT256_SIZE + UINT64_SIZE;
    assert(buf[off + 0] == 0x00 && buf[off + 7] == 0xD2); // 1234567890 in big-endian ends with 0xD2

    memset(&b, 0, sizeof(b));
    assert(block_deserialize(&b, buf, BLOCK_SIZE) == OP_SUCCESS);
    assert(cert_get_id(block_get_cert_ptr(&b)) == cert_get_id(block_get_cert_ptr(&a)));
    assert(uint256_equal(block_get_prev_hash(&b), block_get_prev_hash(&a)));
    assert(*block_get_height(&b) == *block_get_height(&a));
    assert(block_get_timestamp(&b) == block_get_timestamp(&a));

    assert(block_deserialize(&b, buf, BLOCK_SIZE - 1) == OP_BUF_TOO_SMALL);
    assert(block_deserialize(NULL, buf, BLOCK_SIZE) == OP_NULL_PTR);
    assert(block_deserialize(&b, NULL, BLOCK_SIZE) == OP_NULL_PTR);
}

int main(void) {
    test_init_get_set();
    test_copy();
    test_serialize_deserialize();
    return 0;
}
