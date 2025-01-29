#ifndef ATCOMMONS_ENROLL_PARAMS_H
#define ATCOMMONS_ENROLL_PARAMS_H

// #include "enroll_namespace.h"

#include <stdlib.h>
typedef struct {
  char *enrollment_id;
  char *app_name;
  char *device_name;
  char *otp;
  struct enroll_namespace *namespaces; // list of enroll namespaces and their required access for current
  // enrollment
  char *apkam_public_key;
  char *encrypted_default_encryption_private_key;    // apkam symmetric key encrypted default enc private key
  char *encrypted_default_encryption_private_key_iv; // IV that has been used to encrypt the default encryption
                                                     // private key
  char *encrypted_self_encryption_key;               // apkam symmetric key encrypted seld enc key
  char *encrypted_self_encryption_key_iv;            // IV that has been used to encrypt the self encryption key
  char *encrypted_apkam_symmetric_key;
  char *encrypted_apkam_symmetric_key_iv;
  int apkam_keys_expiry_in_millis;
} atauth_enroll_params_t;

/**
 * @brief Initializes the enroll_params_t struct
 *
 * @param ep pointer to the enroll params struct that is to be initialized
 */
void atauth_enroll_params_init(atauth_enroll_params_t *ep);

/**
 * @brief Converts the parameters in an enroll_params_t struct to a json encoded string
 *
 * Note: To calculate expected string len, use method with json_string set to NULL and json_string_size set to 0
 *
 * @param json_string Double pointer to store the json encoded string of provided enroll params
 * @param json_string_len Actual string length written into json_string buffer
 * @param ep Pointer to the enroll_params_t struct whose values need to be converted to a json string
 * @return int 0 for success, non-zero int for failure
 */
int atauth_enroll_params_to_json(const atauth_enroll_params_t *ep, char **json_string);

#endif
