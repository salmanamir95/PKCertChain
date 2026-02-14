#define _POSIX_C_SOURCE 199309L // For clock_gettime
#include "telemetry_core.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h> // For thread ID if needed, or use dummy

#define MAX_OBSERVERS 8

static TelemetryObserver observers[MAX_OBSERVERS];
static int observer_count = 0;

static uint64_t get_current_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void telemetry_init(void) {
    observer_count = 0;
}

void telemetry_register_observer(TelemetryObserver obs) {
    if (observer_count < MAX_OBSERVERS && obs != NULL) {
        observers[observer_count++] = obs;
    }
}

// The "Bus" Dispatcher
void telemetry_push_event(TelemetryEvent* event) {
    // Timestamp at the moment of push
    event->timestamp_ns = get_current_time_ns();
    // event->thread_id = (uint32_t)pthread_self(); // Optional

    // Stage 1: Synchronous dispatch
    // Stage 3: This will become queue_push(event)
    for (int i = 0; i < observer_count; i++) {
        if (observers[i]) {
            observers[i](event);
        }
    }
}

void telemetry_log(SubsystemID subsys, LogLevel level, const char* msg) {
    TelemetryEvent evt;
    evt.subsystem = subsys;
    evt.type = EVENT_LOG;
    evt.data.log.level = level;
    
    // Safe truncation
    strncpy(evt.data.log.msg, msg, sizeof(evt.data.log.msg) - 1);
    evt.data.log.msg[sizeof(evt.data.log.msg) - 1] = '\0';
    
    telemetry_push_event(&evt);
}

void telemetry_metric(SubsystemID subsys, const char* name, double value) {
    TelemetryEvent evt;
    evt.subsystem = subsys;
    evt.type = EVENT_METRIC;
    evt.data.metric.value = value;
    
    strncpy(evt.data.metric.name, name, sizeof(evt.data.metric.name) - 1);
    evt.data.metric.name[sizeof(evt.data.metric.name) - 1] = '\0';
    
    telemetry_push_event(&evt);
}

void telemetry_record_wcet(SubsystemID subsys, const char* func, uint64_t duration_ns) {
    TelemetryEvent evt;
    evt.subsystem = subsys;
    evt.type = EVENT_WCET;
    evt.data.wcet.duration_ns = duration_ns;
    
    strncpy(evt.data.wcet.func_name, func, sizeof(evt.data.wcet.func_name) - 1);
    evt.data.wcet.func_name[sizeof(evt.data.wcet.func_name) - 1] = '\0';
    
    telemetry_push_event(&evt);
}