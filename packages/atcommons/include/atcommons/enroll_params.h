#ifndef ENROLL_PARAMS_H
#define ENROLL_PARAMS_H

#include "enroll_namespace.h"

typedef struct enroll_params_t {
  char *enrollment_id;
  char *app_name;
  char *device_name;
  char *otp;
  /// ToDo: what would be the ideal number of allowed namespaces ?
  enroll_namespace_list_t *ns_list;
  unsigned char *apkam_public_key;
  unsigned char *encrypted_default_encryption_private_key;
  unsigned char *encrypted_default_self_encryption_key;
  unsigned char *encrypted_apkam_symmetric_key;
  int apkam_keys_expiry_in_millis;
} enroll_params;

int enroll_params_init(enroll_params *ep);

int enroll_params_to_json(char **json_string, size_t **json_string_len, const size_t json_string_size,
                          const enroll_params *ep);

#endif
