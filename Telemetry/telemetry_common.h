#ifndef TELEMETRY_COMMON_H
#define TELEMETRY_COMMON_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    SUBSYS_POW,
    SUBSYS_LEDGER,
    SUBSYS_NET,
    SUBSYS_VALIDATION,
    SUBSYS_KERNEL,
    SUBSYS_UNKNOWN
} SubsystemID;

typedef enum {
    EVENT_LOG,
    EVENT_METRIC,
    EVENT_WCET,
    EVENT_BLOCK_VALIDATION_START,
    EVENT_BLOCK_VALIDATION_END,
    EVENT_POW_SOLVE_START,
    EVENT_POW_SOLVE_END
} TelemetryEventType;

typedef enum {
    TEL_LOG_INFO,
    TEL_LOG_WARN,
    TEL_LOG_ERROR,
    TEL_LOG_DEBUG
} LogLevel;

/*
 * TelemetryEvent:
 * Unified event structure.
 * Designed to be copied by value into a ring buffer (approx 160 bytes).
 */
typedef struct {
    uint64_t timestamp_ns;
    TelemetryEventType type;
    SubsystemID subsystem;
    uint32_t thread_id;

    union {
        struct {
            LogLevel level;
            char msg[128];
        } log;
        struct {
            char name[32];
            double value;
        } metric;
        struct {
            char func_name[64];
            uint64_t duration_ns;
        } wcet;
    } data;
} TelemetryEvent;

// Observer Interface
typedef void (*TelemetryObserver)(const TelemetryEvent* event);

#endif // TELEMETRY_COMMON_H