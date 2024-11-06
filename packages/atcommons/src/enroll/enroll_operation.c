#include "atcommons/enroll_operation.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define ENROLL_OPERATION_REQUEST "request"
#define ENROLL_OPERATION_APPROVE "approve"
#define ENROLL_OPERATION_DENY "deny"
#define ENROLL_OPERATION_REVOKE "revoke"
#define ENROLL_OPERATION_UNREVOKE "unrevoke"
#define ENROLL_OPERATION_LIST "list"
#define ENROLL_OPERATION_DELETE "delete"

int enroll_operation_to_string(char **op_name, const enroll_operation_t e_op) {
  int ret = 0;
  if (op_name == NULL) {
    ret = -1;
    return ret;
  }

  switch (e_op) {
  case apkam_request:
    strcpy(*op_name, ENROLL_OPERATION_REQUEST);
    break;
  case apkam_approve:
    strcpy(*op_name, ENROLL_OPERATION_APPROVE);
    break;
  case apkam_deny:
    strcpy(*op_name, ENROLL_OPERATION_DENY);
    break;
  case apkam_revoke:
    strcpy(*op_name, ENROLL_OPERATION_REVOKE);
    break;
  case apkam_unrevoke:
    strcpy(*op_name, ENROLL_OPERATION_UNREVOKE);
    break;
  case apkam_list:
    strcpy(*op_name, ENROLL_OPERATION_LIST);
    break;
  case apkam_delete:
    strcpy(*op_name, ENROLL_OPERATION_DELETE);
    break;
  default:
    ret = 1;
  }
  return ret;
}
