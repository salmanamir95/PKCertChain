#ifndef TIER_H
#define TIER_H

#include "pkcertchain_config.h"

#include <stdint.h>

typedef uint8_t Tier_t;

#define TIER_INVALID 0
#define TIER_SERVER  1
#define TIER_DESKTOP 2
#define TIER_EDGE    3
#define TIER_MCU     4

#endif // TIER_H
