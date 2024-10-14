#ifndef ENROLL_OPERATION_H
#define ENROLL_OPERATION_H

#define ENROLL_OPERATION_REQUEST "request"
#define ENROLL_OPERATION_APPROVE "approve"
#define ENROLL_OPERATION_DENY "deny"
#define ENROLL_OPERATION_REVOKE "revoke"
#define ENROLL_OPERATION_UNREVOKE "unrevoke"
#define ENROLL_OPERATION_LIST "list"
#define ENROLL_OPERATION_DELETE "delete"

#define MAX_ENROLL_OPERATION_STRING_LEN 8

enum ENROLL_OPERATION{
  REQUEST,
  APPROVE,
  DENY,
  REVOKE,
  UNREVOKE,
  LIST,
  DELETE
};

typedef enum ENROLL_OPERATION enroll_operation_t;

/* Converts ENROLL_OPERATION enum to String
 *
 */
int enroll_operation_to_string(char **op_name, enum ENROLL_OPERATION e_op);

#endif