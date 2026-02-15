#ifndef TELEMETRY_CORE_H
#define TELEMETRY_CORE_H

#include "telemetry_common.h"

// Initialize the subsystem
void telemetry_init(void);

// Register a sink (Observer)
void telemetry_register_observer(TelemetryObserver obs);

// Core Dispatch API
void telemetry_push_event(TelemetryEvent* event);

// --- Helper Wrappers ---

void telemetry_log(SubsystemID subsys, LogLevel level, const char* msg);

void telemetry_metric(SubsystemID subsys, const char* name, double value);

// Internal use by WCET macros
void telemetry_record_wcet(SubsystemID subsys, const char* func, uint64_t duration_ns);

#endif // TELEMETRY_CORE_H