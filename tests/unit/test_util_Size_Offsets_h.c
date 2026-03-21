#include <assert.h>
#include "util/Size_Offsets.h"

int main(void) {
    _Static_assert(UINT8_SIZE == 1, "UINT8_SIZE");
    _Static_assert(UINT16_SIZE == 2, "UINT16_SIZE");
    _Static_assert(UINT32_SIZE == 4, "UINT32_SIZE");
    _Static_assert(UINT64_SIZE == 8, "UINT64_SIZE");
    _Static_assert(UINT256_SIZE == 32, "UINT256_SIZE");
    _Static_assert(UINT512_SIZE == 64, "UINT512_SIZE");

    _Static_assert(CERT_SIZE == 65, "CERT_SIZE");
    _Static_assert(BLOCK_SIZE == 146, "BLOCK_SIZE");
    _Static_assert(MINI_POW_CHALLENGE_SIZE == 34, "MINI_POW_CHALLENGE_SIZE");
    _Static_assert(MINI_POW_SOLVE_SIZE == 10, "MINI_POW_SOLVE_SIZE");

    assert(UINT8_SIZE == 1);
    assert(BLOCK_SIZE == 146);
    return 0;
}
