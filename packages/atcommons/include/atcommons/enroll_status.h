#ifndef ENROLL_STATUS_H
#define ENROLL_STATUS_H

enum ENROLL_STATUS {pending, approved, denied, revoked, expired};

int enroll_status_to_string(char *status, enum ENROLL_STATUS es);

#endif