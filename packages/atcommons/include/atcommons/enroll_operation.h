#ifndef ATCOMMONS_ENROLL_OPERATION_H
#define ATCOMMONS_ENROLL_OPERATION_H

#define MAX_ENROLL_OPERATION_STRING_LEN 8

typedef enum {
  atcommons_apkam_request,
  atcommons_apkam_approve,
  atcommons_apkam_deny,
  atcommons_apkam_revoke,
  atcommons_apkam_unrevoke,
  atcommons_apkam_list,
  atcommons_apkam_delete
} atcommons_enroll_operation_t;

/**
 * @brief Parses enroll operation type enroll_operation_t and converts that into a string
 *
 * @param op_name Double pointer to populate the enroll operation name as String(char *)
 * @param e_op enroll operation as enum enroll_operation_t
 * @return int 0 on success, non-zero on failure
 */
int atcommons_enroll_operation_to_string(char **op_name, atcommons_enroll_operation_t e_op);

#endif