#ifndef ENROLL_STATUS_H
#define ENROLL_STATUS_H

#define ENROLL_STATUS_STRING_MAX_LEN 10

typedef enum {
  enroll_status_pending,
  enroll_status_approved,
  enroll_status_denied,
  enroll_status_revoked,
  enroll_status_expired
} enroll_status_t;

/**
 * @brief Parses an enroll_status_t enum value and converts it to string
 *
 * @param status Pointer to populate the enroll status value as string (char *)
 * @param es enroll status value of type eroll_status_t
 * @return int 0 on success, non-zero int on failure
 */
int enroll_status_to_string(char *status, enroll_status_t es);

#endif