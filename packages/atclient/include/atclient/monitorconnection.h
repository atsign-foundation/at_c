#ifndef ATCLIENT_MONITORCONNECTION_H
#define ATCLIENT_MONITORCONNECTION_H

#include "connection.h"
#include "atsign.h"
#include "atevent.h"

#define HEARTBEAT_INVERVAL_MILLIS 30000

typedef struct atclient_monitor_connection_ctx {
    atclient_connection_ctx secondary_connection;
    atsign atsign;
    AtEventQueue queue;
    long long last_heartbeat_sent_time;
    long long last_heartbeat_ack_time;
    long long last_received_time;
    int running;
    int should_be_running;
} atclient_monitor_connection_ctx;

void atclient_monitor_connection_init(atclient_monitor_connection_ctx *ctx, char *atsign_str);

int start_heartbeat(atclient_monitor_connection_ctx *ctx);
int start_heartbeat_impl(atclient_monitor_connection_ctx *ctx);

#endif 