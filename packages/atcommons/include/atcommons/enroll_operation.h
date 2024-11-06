#ifndef ENROLL_OPERATION_H
#define ENROLL_OPERATION_H

#define MAX_ENROLL_OPERATION_STRING_LEN 8

typedef enum {
  apkam_request,
  apkam_approve,
  apkam_deny,
  apkam_revoke,
  apkam_unrevoke,
  apkam_list,
  apkam_delete
} enroll_operation_t;

/**
 * @brief Parses enroll operation type enroll_operation_t and converts that into a string
 *
 * @param op_name Double pointer to populate the enroll operation name as String(char *)
 * @param e_op enroll operation as enum enroll_operation_t
 * @return int 0 on success, non-zero on failure
 */
int enroll_operation_to_string(char **op_name, enroll_operation_t e_op);

#endif