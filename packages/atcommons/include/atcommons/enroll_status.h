#ifndef ENROLL_STATUS_H
#define ENROLL_STATUS_H

#define ENROLL_STATUS_STRING_MAX_LEN 10

enum ENROLL_STATUS {pending, approved, denied, revoked, expired};
typedef enum enroll_status_t;

int enroll_status_to_string(char *status, enum ENROLL_STATUS es);

#endif