#ifndef SER_PRIMITIVE_H
#define SER_PRIMITIVE_H

#include <stdint.h>
#include <string.h>
#include <endian.h>
#include "datatype/OpStatus.h"

#define SER_INLINE static inline __attribute__((always_inline))

/* ----------- WRITE ----------- */

SER_INLINE OpStatus_t uint16_t_serialize(uint16_t v, uint8_t *buf, size_t len)
{
    if (!buf) return OP_NULL_PTR;
    if (len < 2) return OP_BUF_TOO_SMALL;

    uint16_t be = htobe16(v);
    memcpy(buf, &be, 2);

    return OP_SUCCESS;
}

SER_INLINE OpStatus_t uint32_t_serialize(uint32_t v, uint8_t *buf, size_t len)
{
    if (!buf) return OP_NULL_PTR;
    if (len < 4) return OP_BUF_TOO_SMALL;

    uint32_t be = htobe32(v);
    memcpy(buf, &be, 4);

    return OP_SUCCESS;
}

SER_INLINE OpStatus_t uint64_t_serialize(uint64_t v, uint8_t *buf, size_t len)
{
    if (!buf) return OP_NULL_PTR;
    if (len < 8) return OP_BUF_TOO_SMALL;

    uint64_t be = htobe64(v);
    memcpy(buf, &be, 8);

    return OP_SUCCESS;
}

/* ----------- READ ----------- */

SER_INLINE OpStatus_t uint16_t_deserialize(uint16_t *out, const uint8_t *buf, size_t len)
{
    if (!out || !buf) return OP_NULL_PTR;
    if (len < 2) return OP_BUF_TOO_SMALL;

    uint16_t tmp;
    memcpy(&tmp, buf, 2);
    *out = be16toh(tmp);

    return OP_SUCCESS;
}

SER_INLINE OpStatus_t uint32_t_deserialize(uint32_t *out, const uint8_t *buf, size_t len)
{
    if (!out || !buf) return OP_NULL_PTR;
    if (len < 4) return OP_BUF_TOO_SMALL;

    uint32_t tmp;
    memcpy(&tmp, buf, 4);
    *out = be32toh(tmp);

    return OP_SUCCESS;
}

SER_INLINE OpStatus_t uint64_t_deserialize(uint64_t *out, const uint8_t *buf, size_t len)
{
    if (!out || !buf) return OP_NULL_PTR;
    if (len < 8) return OP_BUF_TOO_SMALL;

    uint64_t tmp;
    memcpy(&tmp, buf, 8);
    *out = be64toh(tmp);

    return OP_SUCCESS;
}

#endif
