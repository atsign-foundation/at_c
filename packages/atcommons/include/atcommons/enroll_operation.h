#ifndef ENROLL_OPERATION_H
#define ENROLL_OPERATION_H

enum ENROLL_OPERATION { request, approve, deny, revoke, unrevoke, list, delete };

int enroll_operation_to_string(char **op_name, const enum ENROLL_OPERATION e_op);

#endif