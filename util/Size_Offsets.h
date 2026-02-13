#ifndef SIZE_OFFSETS_H
#define SIZE_OFFSETS_H

// Primitive sizes
#define UINT8_SIZE    1
#define UINT16_SIZE   2
#define UINT32_SIZE   4
#define UINT64_SIZE   8
#define UINT256_SIZE  32
#define UINT512_SIZE  64


// Struct sizes (total serialized size)
#define CERT_SIZE    (UINT8_SIZE + 2*UINT256_SIZE)      // 1 + 32 + 32 = 65
#define BLOCK_SIZE   (CERT_SIZE + UINT64_SIZE + UINT8_SIZE) // 65 + 8 + 1 = 74

#define MINI_POW_CHALLENGE_SIZE (UINT256_SIZE + 2*UINT8_SIZE) // example
#define MINI_POW_SOLVE_SIZE     (UINT64_SIZE + UINT8_SIZE)

#endif
