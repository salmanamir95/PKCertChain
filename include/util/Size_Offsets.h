#ifndef SIZE_OFFSETS_H
#define SIZE_OFFSETS_H

// Primitive sizes
#define UINT8_SIZE 1
#define UINT16_SIZE 2
#define UINT32_SIZE 4
#define UINT64_SIZE 8
#define UINT256_SIZE 32
#define UINT512_SIZE 64

// Struct sizes (total serialized size)
#define CERT_SIZE (UINT8_SIZE + 2 * UINT256_SIZE)                            // 1 + 32 + 32 = 65
#define BLOCK_SIZE (CERT_SIZE + 2*UINT64_SIZE + UINT8_SIZE + UINT256_SIZE * 2) //BLOCK_SIZE = 146 bytes

#define MINI_POW_CHALLENGE_SIZE (UINT256_SIZE + 2 * UINT8_SIZE) // 34 bytes
#define MINI_POW_SOLVE_SIZE (UINT64_SIZE + UINT8_SIZE + UINT8_SIZE) //10 bytes

#endif
