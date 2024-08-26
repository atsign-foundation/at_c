#ifndef ATCLIENT_NOTIFY_H
#define ATCLIENT_NOTIFY_H

#include "atclient/atclient.h"
#include "atclient/notify_params.h"

int atclient_notify(atclient *ctx, const atclient_notify_params *params, char **notification_id);

#endif // ATCLIENT_NOTIFY_H
