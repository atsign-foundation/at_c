#ifndef ATAUTH_APKAM_KEYS_H
#define ATAUTH_APKAM_KEYS_H
#include "atclient/atkeys.h"
#ifdef __cplusplus
extern "C" {
#endif
#include <stdlib.h>

struct atauth_apkam_keys {
  unsigned char *apkam_symmetric_key_bytes;
  char *apkam_symmetric_key_base64;
  char *pkam_public_key_base64;
  char *pkam_private_key_base64;
  char *encrypt_public_key_base64;
  char *encrypt_private_key_base64;
  unsigned char *self_encryption_key_bytes;
  char *self_encryption_key_base64;
  char *encrypted_encrypt_private_key_base64;
  size_t encrypted_encrypt_private_key_base64_len;
  char *encrypted_encrypt_private_iv_base64;
  char *encrypted_self_encryption_key_base64;
  size_t encrypted_self_encryption_key_base64_len;
  char *encrypted_self_encryption_key_iv_base64;
};

void atauth_apkam_keys_init(struct atauth_apkam_keys *keys);
int atauth_apkam_keys_generate_all(struct atauth_apkam_keys *keys);
void atauth_apkam_keys_free(struct atauth_apkam_keys *keys);

int atauth_apkam_keys_create_atkeys(const struct atauth_apkam_keys *keys, atclient_atkeys **atkeys_out);
#ifdef __cplusplus
}
#endif

#endif
