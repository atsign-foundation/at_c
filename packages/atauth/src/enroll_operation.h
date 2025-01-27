#ifndef ATCOMMONS_ENROLL_OPERATION_H
#define ATCOMMONS_ENROLL_OPERATION_H

#define MAX_ENROLL_OPERATION_STRING_LEN 8

typedef enum {
  atauth_apkam_request,
  atauth_apkam_approve,
  atauth_apkam_deny,
  atauth_apkam_revoke,
  atauth_apkam_unrevoke,
  atauth_apkam_list,
  atauth_apkam_delete
} atauth_enroll_operation_t;

extern const char *atauth_enroll_operation_map[];
#endif
