#ifndef ATAUTH_ENROLL_RESPONSE_H
#define ATAUTH_ENROLL_RESPONSE_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

struct enroll_response {
  const char *enrollment_id;
  const char *status;
};

int parse_enrollment_response(const char *buffer, struct enroll_response *response);

void free_enroll_response(struct enroll_response *res);

#ifdef __cplusplus
}
#endif
#endif
