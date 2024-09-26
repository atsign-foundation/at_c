#ifndef ENROLL_OPERATION_H
#define ENROLL_OPERATION_H

enum EnrollOperation { request, approve, deny, revoke, unrevoke, list, delete };

int enroll_operation_to_string(char **op_name, const enum EnrollOperation e_op);

#endif