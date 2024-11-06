#include "atcommons/enroll_status.h"

#include <stddef.h>
#include <string.h>

int enroll_status_to_string(char *status, const enroll_status_t es) {
  int ret = 0;
  if (status == NULL) {
    ret = -1;
    goto exit;
  }

  switch (es) {
    case enroll_status_pending:
      strncpy(status, "pending", ENROLL_STATUS_STRING_MAX_LEN);
    case enroll_status_approved:
      strncpy(status, "approved", ENROLL_STATUS_STRING_MAX_LEN);
    case enroll_status_denied:
      strncpy(status, "denied", ENROLL_STATUS_STRING_MAX_LEN);
    case enroll_status_revoked:
      strncpy(status, "revoked", ENROLL_STATUS_STRING_MAX_LEN);
    case enroll_status_expired:
      strncpy(status, "expired", ENROLL_STATUS_STRING_MAX_LEN);
    default:
      ret = -1;
  }

  exit: { return ret; }
}
