#ifndef ENROLL_PARAMS_H
#define ENROLL_PARAMS_H

#include "enroll_namespace.h"

typedef struct {
  char *enrollment_id;
  char *app_name;
  char *device_name;
  char *otp;
  enroll_namespace_list_t *ns_list; // list of enroll namespaces and their required access for current enrollment
  unsigned char *apkam_public_key;
  unsigned char *encrypted_default_encryption_private_key; // apkam symmetric key encrypted default enc private key
  unsigned char *encrypted_self_encryption_key; // apkam symmetric key encrypted seld enc key
  unsigned char *encrypted_apkam_symmetric_key;
  int apkam_keys_expiry_in_millis;
} enroll_params_t;

/**
 * @brief Initializes the enroll_params_t struct
 *
 * @param ep pointer to the enroll params struct that is to be initialized
 * @return int 0 on success, non-zero int on failure
 */
int enroll_params_init(enroll_params_t *ep);

/**
 * @brief Converts the parameters in an enroll_params_t struct to a json encoded string
 *
 * Note: Can be used with json_string set to null to calculate the expected size of the json string
 *
 * @param json_string Double pointer to store the json encoded string of provided enroll params
 * @param json_string_len Actual string length written into json_string buffer
 * @param json_string_size Allocated memory size for json_string buffer
 * @param ep Pointer to the enroll_params_t struct whose values need to be converted to a json string
 * @return int 0 for success, non-zero int for failure
 */
int enroll_params_to_json(char **json_string, size_t *json_string_len, size_t json_string_size,
                          const enroll_params_t *ep);

#endif
