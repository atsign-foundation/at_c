#include "atcommons/enroll_status.h"

#include <stddef.h>
#include <string.h>

int enroll_status_to_string(char *status, const atcommons_enroll_status_t es) {
  int ret = 0;
  if (status == NULL) {
    ret = -1;
    goto exit;
  }

  switch (es) {
    case atcommons_enroll_status_pending:
      strncpy(status, "pending", ATCOMMONS_ENROLL_STATUS_STRING_MAX_LEN);
    case atcommons_enroll_status_approved:
      strncpy(status, "approved", ATCOMMONS_ENROLL_STATUS_STRING_MAX_LEN);
    case atcommons_enroll_status_denied:
      strncpy(status, "denied", ATCOMMONS_ENROLL_STATUS_STRING_MAX_LEN);
    case atcommons_enroll_status_revoked:
      strncpy(status, "revoked", ATCOMMONS_ENROLL_STATUS_STRING_MAX_LEN);
    case atcommons_enroll_status_expired:
      strncpy(status, "expired", ATCOMMONS_ENROLL_STATUS_STRING_MAX_LEN);
    default:
      ret = -1;
  }

  exit: { return ret; }
}
