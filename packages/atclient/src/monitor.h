#ifndef ATCLIENT_SRC_MONITOR_H
#define ATCLIENT_SRC_MONITOR_H
#ifdef __cplusplus
extern "C" {
#endif

// This file is the visible for testing header
// See the include below for the public header
#include <atclient/monitor.h>

int populate_monitor_message(atclient_monitor_message *);
int populate_monitor_data_message(atclient_monitor_message *);
int populate_monitor_error_message(atclient_monitor_message *);
int populate_monitor_notification_message(atclient_monitor_message *);

int decrypt_notification(atclient *monitor_conn, atclient_atnotification *notification);

#ifdef __cplusplus
}
#endif
#endif
