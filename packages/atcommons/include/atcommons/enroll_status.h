#ifndef ENROLL_STATUS_H
#define ENROLL_STATUS_H

enum EnrollStatus {pending, approved, denied, revoked, expired};

int enroll_status_to_string(char *status, enum EnrollStatus es);

#endif