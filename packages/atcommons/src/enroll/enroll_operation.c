#include "atcommons/enroll_operation.h"

#include <stddef.h>

#define ENROLL_OPERATION_REQUEST "request"
#define ENROLL_OPERATION_APPROVE "approve"
#define ENROLL_OPERATION_DENY "deny"
#define ENROLL_OPERATION_REVOKE "revoke"
#define ENROLL_OPERATION_UNREVOKE "unrevoke"
#define ENROLL_OPERATION_LIST "list"
#define ENROLL_OPERATION_DELETE "delete"


int enroll_operation_to_string(char **op_name, const enum ENROLL_OPERATION e_op) {
    int ret = 0;
    if (op_name == NULL) {
        ret = -1;
        return ret;
    }

    switch (e_op) {
        case request:
            *op_name = &ENROLL_OPERATION_REQUEST[0]; //point op_name to the first char of the operation name
            break;
        case approve:
            *op_name = &ENROLL_OPERATION_APPROVE[0];
            break;
        case deny:
            *op_name = &ENROLL_OPERATION_DENY[0];
            break;
        case revoke:
            *op_name = &ENROLL_OPERATION_REVOKE[0];
            break;
        case unrevoke:
            *op_name = &ENROLL_OPERATION_UNREVOKE[0];
            break;
        case list:
            *op_name = &ENROLL_OPERATION_LIST[0];
            break;
        case delete:
            *op_name = &ENROLL_OPERATION_DELETE[0];
            break;
        default:
            ret = -1;
    }

    return ret;
}
