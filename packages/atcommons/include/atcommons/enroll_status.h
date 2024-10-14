#ifndef ENROLL_STATUS_H
#define ENROLL_STATUS_H

enum ENROLL_STATUS {pending, approved, denied, revoked, expired};
typedef enum enroll_status_t;

int enroll_status_to_string(char *status, enum ENROLL_STATUS es);

#endif