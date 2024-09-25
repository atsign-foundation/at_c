#include "atcommons/enroll_status.h"

#include <stddef.h>

int enroll_status_to_string(char *status, const enum ENROLL_STATUS es) {
  int ret = 0;
  if (status == NULL) {
    ret = -1;
    goto exit;
  }

  switch (es) {
    case pending:
      *status = "pending";
    case approved:
      *status = "approved";
    case denied:
      *status = "denied";
    case revoked:
      *status = "revoked";
    case expired:
      *status = "expired";
    default:
      ret = -1;
  }

  exit: { return ret; }
}
