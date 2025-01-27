#ifndef ATAUTH_ENROLL_REQUEST_H
#define ATAUTH_ENROLL_REQUEST_H

#include "atclient/atclient.h"
#ifdef __cplusplus
extern "C" {
#endif

#include "enroll_operation.h"
#include "enroll_params.h"
#include "enroll_response.h"
int atauth_generate_enroll_command_string(const atauth_enroll_params_t *params,
                                          const atauth_enroll_operation_t operation, char **command_string);

int atauth_send_enroll_request(atclient *atclient, const atauth_enroll_params_t *params,
                               const atauth_enroll_operation_t operation, struct enroll_response *response);
#ifdef __cplusplus
}
#endif
#endif
