#ifndef WCET_H
#define WCET_H

#include "telemetry_core.h"
#include <time.h>

// Internal structure to hold scope state
typedef struct {
    uint64_t start_time;
    SubsystemID subsys;
    const char* name;
} TelemetryScope;

static inline uint64_t wcet_now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Cleanup function called automatically when scope ends
static inline void telemetry_scope_cleanup(TelemetryScope* scope) {
    uint64_t end = wcet_now_ns();
    uint64_t duration = end - scope->start_time;
    
    // Dispatch the WCET event
    telemetry_record_wcet(scope->subsys, scope->name, duration);
}

// Constructor for the scope
static inline TelemetryScope telemetry_scope_begin(SubsystemID subsys, const char* name) {
    TelemetryScope scope;
    scope.start_time = wcet_now_ns();
    scope.subsys = subsys;
    scope.name = name;
    return scope;
}

/*
 * Usage:
 * void my_heavy_function() {
 *     TELEMETRY_SCOPE(SUBSYS_POW, "heavy_calc");
 *     // ... code ...
 * } // Event automatically fired here
 */
#define TELEMETRY_SCOPE(subsys, name) \
    TelemetryScope scope_##__LINE__ __attribute__((cleanup(telemetry_scope_cleanup))) = \
    telemetry_scope_begin(subsys, name)

#endif // WCET_H