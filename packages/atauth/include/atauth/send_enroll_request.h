#ifndef ATAUTH_SEND_ENROLL_REQUEST
#define ATAUTH_SEND_ENROLL_REQUEST

#include "../../../atclient/include/atclient/atclient.h"
// #include <atclient/atclient.h>
#include <atcommons/enroll_params.h>
#include <stddef.h>

#define TAG "send_enroll_request"
#define ENROLL_ID_MAX_LEN 50

/**
 *
 */
int atauth_send_enroll_request(char *enroll_id, char *enroll_status, atclient *atclient, enroll_params_t *ep);

#endif