#ifndef ATCLIENT_NOTIFY_H
#define ATCLIENT_NOTIFY_H
#ifdef __cplusplus
extern "C" {
#endif

#include "atclient/atclient.h"
#include "atclient/notify_params.h"
#include <atchops/platform.h> // IWYU pragma: keep

int atclient_notify(atclient *ctx, const atclient_notify_params *params, char **notification_id);

#ifdef __cplusplus
}
#endif
#endif // ATCLIENT_NOTIFY_H
