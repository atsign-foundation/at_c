#ifndef ATAUTH_APKAM_KEYS_H
#define ATAUTH_APKAM_KEYS_H
#include "atclient/atkeys.h"
#ifdef __cplusplus
extern "C" {
#endif
#include <stdlib.h>

// Struct that contains symmetric key, as well as an encrypted copy of the key
struct atauth_apkam_symmetric_key {
  unsigned char *symmetric_key_raw;
  char *symmetric_key_base64;
  char *encrypted_symmetric_key_base64;
  size_t symmetric_key_raw_len;
  size_t symmetric_key_base64_len;
  size_t encrypted_symmetric_key_base64_len;
};

void atauth_apkam_symmetric_key_init(struct atauth_apkam_symmetric_key *);
int atauth_apkam_symmetric_key_generate(struct atauth_apkam_symmetric_key *, const atchops_rsa_key_public_key *);
void atauth_apkam_symmetric_key_free(struct atauth_apkam_symmetric_key *);

// keys used for the first enrollment
struct atauth_generated_first_enrollment_keys {
  char *apkam_public_key;
  char *apkam_private_key;

  char *encrypt_public_key;
  char *encrypt_private_key;

  unsigned char *self_encryption_key_raw;
  size_t self_encryption_key_raw_len;

  char *self_encryption_key_base64;
  size_t self_encryption_key_base64_len;
};

void atauth_generated_first_enrollment_keys_init(struct atauth_generated_first_enrollment_keys *);
int atauth_generated_first_enrollment_keys_generate(struct atauth_generated_first_enrollment_keys *);
int atauth_generated_first_enrollment_keys_populate_atkeys(const struct atauth_generated_first_enrollment_keys *,
                                                           atclient_atkeys *);
void atauth_generated_first_enrollment_keys_free(struct atauth_generated_first_enrollment_keys *);

// keys used for every new apkam enrollment
struct atauth_generated_apkam_enrollment_keys {
  char *apkam_public_key;
  char *apkam_private_key;
  struct atauth_apkam_symmetric_key apkam_symmetric_key;
};

void atauth_generated_apkam_enrollment_keys_init(struct atauth_generated_apkam_enrollment_keys *);
int atauth_generated_apkam_enrollment_keys_generate(struct atauth_generated_apkam_enrollment_keys *,
                                                    const atchops_rsa_key_public_key *);
int atauth_generated_apkam_enrollment_keys_populate_atkeys(const struct atauth_generated_apkam_enrollment_keys *,
                                                           atclient_atkeys *);
void atauth_generated_apkam_enrollment_keys_free(struct atauth_generated_apkam_enrollment_keys *);
#ifdef __cplusplus
}
#endif
#endif
