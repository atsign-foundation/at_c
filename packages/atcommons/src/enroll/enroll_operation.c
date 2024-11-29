#include "atcommons/enroll_operation.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define ATCOMMONS_ENROLL_OPERATION_REQUEST "request"
#define ATCOMMONS_ENROLL_OPERATION_APPROVE "approve"
#define ATCOMMONS_ENROLL_OPERATION_DENY "deny"
#define ATCOMMONS_ENROLL_OPERATION_REVOKE "revoke"
#define ATCOMMONS_ENROLL_OPERATION_UNREVOKE "unrevoke"
#define ATCOMMONS_ENROLL_OPERATION_LIST "list"
#define ATCOMMONS_ENROLL_OPERATION_DELETE "delete"

int atcommons_enroll_operation_to_string(char **op_name, const atcommons_enroll_operation_t e_op) {
  int ret = 0;
  if (op_name == NULL) {
    ret = -1;
    return ret;
  }

  switch (e_op) {
  case atcommons_apkam_request:
    strcpy(*op_name, ATCOMMONS_ENROLL_OPERATION_REQUEST);
    break;
  case atcommons_apkam_approve:
    strcpy(*op_name, ATCOMMONS_ENROLL_OPERATION_APPROVE);
    break;
  case atcommons_apkam_deny:
    strcpy(*op_name, ATCOMMONS_ENROLL_OPERATION_DENY);
    break;
  case atcommons_apkam_revoke:
    strcpy(*op_name, ATCOMMONS_ENROLL_OPERATION_REVOKE);
    break;
  case atcommons_apkam_unrevoke:
    strcpy(*op_name, ATCOMMONS_ENROLL_OPERATION_UNREVOKE);
    break;
  case atcommons_apkam_list:
    strcpy(*op_name, ATCOMMONS_ENROLL_OPERATION_LIST);
    break;
  case atcommons_apkam_delete:
    strcpy(*op_name, ATCOMMONS_ENROLL_OPERATION_DELETE);
    break;
  default:
    ret = 1;
  }
  return ret;
}
