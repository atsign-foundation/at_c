#ifndef ATAUTH_WAIT_FOR_ENROLLMENT_H
#define ATAUTH_WAIT_FOR_ENROLLMENT_H
#ifdef __cplusplus
extern "C" {
#endif
#include "atclient/atclient.h"

int wait_for_enrollment(atclient *ctx, const char *atsign, const atclient_atkeys *atkeys,
                        const atclient_authenticate_options *opts);

int is_enrollment_denied(const char *err_msg);
int is_enrollment_pending(const char *err_msg);

#ifdef __cplusplus
}
#endif
#endif
