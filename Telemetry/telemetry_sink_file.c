#include "telemetry_core.h"
#include <stdio.h>

static FILE* log_file = NULL;

void file_sink_observer(const TelemetryEvent* event) {
    if (!log_file) return;

    switch (event->type) {
        case EVENT_LOG:
            fprintf(log_file, "[LOG] [%lu] Subsys:%d Level:%d Msg: %s\n", 
                event->timestamp_ns, event->subsystem, event->data.log.level, event->data.log.msg);
            break;
        case EVENT_METRIC:
            fprintf(log_file, "[METRIC] [%lu] Subsys:%d %s: %f\n", 
                event->timestamp_ns, event->subsystem, event->data.metric.name, event->data.metric.value);
            break;
        case EVENT_WCET:
            fprintf(log_file, "[WCET] [%lu] Subsys:%d Func:%s Duration:%lu ns\n", 
                event->timestamp_ns, event->subsystem, event->data.wcet.func_name, event->data.wcet.duration_ns);
            break;
        default:
            break;
    }
    fflush(log_file);
}

void telemetry_sink_file_init(const char* filename) {
    log_file = fopen(filename, "w");
    if (log_file) {
        telemetry_register_observer(file_sink_observer);
    }
}