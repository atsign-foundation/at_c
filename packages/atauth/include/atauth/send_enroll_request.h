#ifndef ATAUTH_SEND_ENROLL_REQUEST
#define ATAUTH_SEND_ENROLL_REQUEST

#include <atclient/atclient.h>
#include <atcommons/enroll_params.h>

#define ENROLL_ID_MAX_LEN 50

/**
 * @brief Sends an enrollment request to the server. Then parses and returns the enrollment ID and status.
 *
*
 * @param client Pointer to an authenticated instance of atclient
 * @param ep Pointer to the `enroll_params_t` structure containing enrollment request parameters
 * @param enroll_id buffer where the enrollment ID will be stored. Memory should be allocated by caller.
 *                  Allocation size should be ENROLL_ID_MAX_LEN
 * @param enroll_status Pointer to a buffer where the enrollment status will be stored
 *
 * @returns 0 on success, non-zero error code on failure.
 */
int atauth_send_enroll_request(atclient *client, const atcommons_enroll_params_t *ep, char *enroll_id, char *enroll_status);

#endif