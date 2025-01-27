#include "enroll_operation.h"

#include <stddef.h>
#include <stdlib.h>

#define ATAUTH_ENROLL_OPERATION_REQUEST "request"
#define ATAUTH_ENROLL_OPERATION_APPROVE "approve"
#define ATAUTH_ENROLL_OPERATION_DENY "deny"
#define ATAUTH_ENROLL_OPERATION_REVOKE "revoke"
#define ATAUTH_ENROLL_OPERATION_UNREVOKE "unrevoke"
#define ATAUTH_ENROLL_OPERATION_LIST "list"
#define ATAUTH_ENROLL_OPERATION_DELETE "delete"

const char *atauth_enroll_operation_map[] = {
    [atauth_apkam_request] = ATAUTH_ENROLL_OPERATION_REQUEST,
    [atauth_apkam_approve] = ATAUTH_ENROLL_OPERATION_APPROVE,
    [atauth_apkam_deny] = ATAUTH_ENROLL_OPERATION_DENY,
    [atauth_apkam_revoke] = ATAUTH_ENROLL_OPERATION_REVOKE,
    [atauth_apkam_unrevoke] = ATAUTH_ENROLL_OPERATION_UNREVOKE,
    [atauth_apkam_list] = ATAUTH_ENROLL_OPERATION_LIST,
    [atauth_apkam_delete] = ATAUTH_ENROLL_OPERATION_DELETE,
};
