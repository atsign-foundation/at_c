#include "atcommons/enroll_operation.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int enroll_operation_to_string(char **op_name, enum ENROLL_OPERATION e_op) {
  int ret = 0;
  if (op_name == NULL) {
    ret = -1;
    return ret;
  }

  switch (e_op) {
  case REQUEST:
    strcpy(*op_name, ENROLL_OPERATION_REQUEST);
    break;
  case APPROVE:
    strcpy(*op_name, ENROLL_OPERATION_APPROVE);
    break;
  case DENY:
    strcpy(*op_name, ENROLL_OPERATION_DENY);
    break;
  case REVOKE:
    strcpy(*op_name, ENROLL_OPERATION_REVOKE);
    break;
  case UNREVOKE:
    strcpy(*op_name, ENROLL_OPERATION_UNREVOKE);
    break;
  case LIST:
    strcpy(*op_name, ENROLL_OPERATION_LIST);
    break;
  case DELETE:
    strcpy(*op_name, ENROLL_OPERATION_DELETE);
    break;
  default:
    ret = 1;
  }
  return ret;
}
