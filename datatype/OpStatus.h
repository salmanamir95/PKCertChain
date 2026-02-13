#ifndef OP_STATUS_H
#define OP_STATUS_H

#include <stdint.h>

typedef uint8_t OpStatus_t;

#define OP_NULL_PTR      0
#define OP_BUF_TOO_SMALL 1
#define OP_INVALID_INPUT 2
#define OP_SUCCESS       3
#endif // OP_STATUS_H