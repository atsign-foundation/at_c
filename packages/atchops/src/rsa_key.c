#include "atchops/rsa_key.h"
#include "atchops/base64.h"
#include "atchops/constants.h"
#include "atchops/mbedtls.h"
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "rsa_key"

void atchops_rsa_key_public_key_init(atchops_rsa_key_public_key *public_key) {
  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return;
  }

  /*
   * 2. Initialize the key
   */
  memset(public_key, 0, sizeof(atchops_rsa_key_public_key));
}

void atchops_rsa_key_public_key_free(atchops_rsa_key_public_key *public_key) {
  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return;
  }

  /*
   * 2. Free the key
   */
  if (atchops_rsa_key_public_key_is_n_initialized(public_key)) {
    atchops_rsa_key_public_key_unset_n(public_key);
  }

  if (atchops_rsa_key_public_key_is_e_initialized(public_key)) {
    atchops_rsa_key_public_key_unset_e(public_key);
  }
  memset(public_key, 0, sizeof(atchops_rsa_key_public_key));
}

void atchops_rsa_key_private_key_init(atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Initialize the key
   */
  memset(private_key, 0, sizeof(atchops_rsa_key_private_key));
}

void atchops_rsa_key_private_key_free(atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Free the key
   */
  if (atchops_rsa_key_private_key_is_n_initialized(private_key)) {
    atchops_rsa_key_private_key_unset_n(private_key);
  }

  if (atchops_rsa_key_private_key_is_e_initialized(private_key)) {
    atchops_rsa_key_private_key_unset_e(private_key);
  }

  if (atchops_rsa_key_private_key_is_d_initialized(private_key)) {
    atchops_rsa_key_private_key_unset_d(private_key);
  }

  if (atchops_rsa_key_private_key_is_p_initialized(private_key)) {
    atchops_rsa_key_private_key_unset_p(private_key);
  }

  if (atchops_rsa_key_private_key_is_q_initialized(private_key)) {
    atchops_rsa_key_private_key_unset_q(private_key);
  }
  memset(private_key, 0, sizeof(atchops_rsa_key_private_key));
}

int atchops_rsa_key_public_key_clone(const atchops_rsa_key_public_key *src, atchops_rsa_key_public_key *dst) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (src == NULL || dst == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "src or dst is null\n");
    return ret;
  }

  /*
   * 2. Clone the key
   */
  if ((ret = atchops_rsa_key_public_key_set_n(dst, src->n.value, src->n.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_public_key_set_e(dst, src->e.value, src->e.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set e\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atchops_rsa_key_private_key_clone(const atchops_rsa_key_private_key *src, atchops_rsa_key_private_key *dst) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (src == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "src is null\n");
    return ret;
  }

  if (dst == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "dst is null\n");
    return ret;
  }

  /*
   * 2. Clone the key
   */
  if ((ret = atchops_rsa_key_private_key_set_n(dst, src->n.value, src->n.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_private_key_set_e(dst, src->e.value, src->e.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set e\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_private_key_set_d(dst, src->d.value, src->d.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set d\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_private_key_set_p(dst, src->p.value, src->p.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set p\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_private_key_set_q(dst, src->q.value, src->q.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set q\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atchops_rsa_key_generate(atchops_rsa_key_public_key *public_key, atchops_rsa_key_private_key *private_key) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return ret;
  }

  if (private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  const size_t public_key_base64_size = 1024; // 1024 bytes is sufficient size for a 2048 bit RSA key base64 encoded
  char public_key_base64[public_key_base64_size];
  memset(public_key_base64, 0, sizeof(char) * public_key_base64_size);

  const size_t private_key_base64_size = 2048; // 2048 bytes is sufficient size for a 2048 bit RSA key base64 encoded
  char private_key_base64[private_key_base64_size];
  memset(private_key_base64, 0, sizeof(char) * private_key_base64_size);

  unsigned char *private_key_non_base64 =
      NULL; // holds the raw bytes of the 9 element SEQUENCE of the numbers (0, N, E, D, P, Q, DP, DQ, QP), free later

  unsigned char *private_key_pkcs8 = NULL; // buffer for building the pkcs_8 formatted private key, free later
  char *private_key_pkcs8_base64 = NULL;   // to hold the base64-encoded pkcs 8 formatted private key, free later

  const size_t temp_buf_size = 4096; // sufficient to hold a private RSA Key in format ----BEGIN ....
  unsigned char temp_buf[temp_buf_size];

  /*
   * 3. Seed RNG
   */
  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char *)ATCHOPS_RNG_PERSONALIZATION,
                                   strlen(ATCHOPS_RNG_PERSONALIZATION))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to seed random number generator\n");
    goto exit;
  }

  /*
   * 4. Use MbedTLS to generate RSA key pair
   */
  if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to setup RSA key\n");
    goto exit;
  }

  if ((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to generate RSA key\n");
    goto exit;
  }

  /*
   * 5. Write to public_key_base64 buffer
   */
  memset(temp_buf, 0, sizeof(temp_buf));
  if ((ret = mbedtls_pk_write_pubkey_pem(&pk, temp_buf, temp_buf_size)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to write public key\n");
    goto exit;
  }

  size_t public_key_base64_len = 0;
  char *begin = strstr((char *)temp_buf, "-----BEGIN PUBLIC KEY-----");
  char *end = strstr((char *)temp_buf, "-----END PUBLIC KEY-----");
  if (begin != NULL && end != NULL) {

    begin += strlen("-----BEGIN PUBLIC KEY-----");
    while (*begin == '\n' || *begin == '\r' || *begin == ' ')
      begin++;

    for (char *src = begin, *dest = public_key_base64; src < end; ++src) {
      if (*src != '\n' && *src != '\r') {
        *dest++ = *src;
        public_key_base64_len++;
      }
    }
  }

  /*
   * 6. Write to private_key_base64 buffer (PKCS#8 format)
   */
  memset(temp_buf, 0, sizeof(unsigned char) * temp_buf_size);
  if ((ret = mbedtls_pk_write_key_pem(&pk, temp_buf, temp_buf_size)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to write private key (PKCS#8 format)\n");
    goto exit;
  }

  size_t private_key_base64_len = 0;
  begin = strstr((char *)temp_buf, "-----BEGIN RSA PRIVATE KEY-----");
  end = strstr((char *)temp_buf, "-----END RSA PRIVATE KEY-----");
  if (begin != NULL && end != NULL) {
    begin += strlen("-----BEGIN RSA PRIVATE KEY-----");
    while (*begin == '\n' || *begin == '\r' || *begin == ' ')
      begin++;

    for (char *src = begin, *dest = private_key_base64; src < end; ++src) {
      if (*src != '\n' && *src != '\r') {
        *dest++ = *src;
        private_key_base64_len++;
      }
    }
  }

  const size_t private_key_non_base64_size = atchops_base64_decoded_size(private_key_base64_len);
  private_key_non_base64 = (unsigned char *)malloc(private_key_non_base64_size);
  if (private_key_non_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for private_key_non_base64\n");
    goto exit;
  }

  size_t private_key_non_base64_len = 0;
  if ((ret = atchops_base64_decode((const unsigned char *)private_key_base64, private_key_base64_len,
                                   private_key_non_base64, private_key_non_base64_size, &private_key_non_base64_len)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to decode private key\n");
    goto exit;
  }

  const size_t private_key_pkcs8_size = private_key_non_base64_len + 22;
  private_key_pkcs8 = (unsigned char *)malloc(private_key_pkcs8_size);
  if (private_key_pkcs8 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for private_key_pkcs8\n");
    goto exit;
  }
  memset(private_key_pkcs8, 0, sizeof(unsigned char) * private_key_pkcs8_size);


  // https://lapo.it/asn1js/ use this to debug
  // PrivateKeyInfo SEQUENCE (3 elements)
  private_key_pkcs8[0] = 0x30; // constructed sequence tag
  private_key_pkcs8[1] = 0x82; // 8 --> 1000 0000 (1 in MSB means that it is long form) and 2 --> 0010 0000 (the next 2
                               // bytes are the length of data)
  private_key_pkcs8[2] = (unsigned char)((private_key_pkcs8_size >> 8) & 0xFF);
  private_key_pkcs8[3] = (unsigned char)(private_key_pkcs8_size & 0xFF);

  // version INTEGER 0
  private_key_pkcs8[4] = 0x02; // integer tag
  private_key_pkcs8[5] = 0x01; // length of data
  private_key_pkcs8[6] = 0x00; // data

  // private key algorithm identifier
  private_key_pkcs8[7] = 0x30; // constructed sequence tag
  private_key_pkcs8[8] = 0x0D; // there are 2 elements in the sequence
  private_key_pkcs8[9] = 0x06;
  private_key_pkcs8[10] = 0x09;
  private_key_pkcs8[11] = 0x2A;
  private_key_pkcs8[12] = 0x86;
  private_key_pkcs8[13] = 0x48;
  private_key_pkcs8[14] = 0x86;
  private_key_pkcs8[15] = 0xF7;
  private_key_pkcs8[16] = 0x0D;
  private_key_pkcs8[17] = 0x01;
  private_key_pkcs8[18] = 0x01;
  private_key_pkcs8[19] = 0x01;
  private_key_pkcs8[20] = 0x05;
  private_key_pkcs8[21] = 0x00;

  // PrivateKey OCTET STRING
  private_key_pkcs8[22] = 0x04; // octet string tag
  private_key_pkcs8[23] = 0x82; // 8 --> 1000 0000 (1 in MSB means that it is long form) and 2 --> 0010 0000 (the next 2
                                // bytes are the length of data)
  private_key_pkcs8[24] = (unsigned char)((private_key_non_base64_len >> 8) & 0xFF); // length of data
  private_key_pkcs8[25] = (unsigned char)(private_key_non_base64_len & 0xFF);        // length of data

  memcpy(private_key_pkcs8 + 26, private_key_non_base64, private_key_non_base64_len);

  const size_t private_key_base64_pkcs8_size = atchops_base64_encoded_size(private_key_non_base64_len);
  private_key_pkcs8_base64 = (char *)malloc(private_key_base64_pkcs8_size);
  if (private_key_pkcs8_base64 == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for private_key_pkcs8_base64\n");
    goto exit;
  }
  memset(private_key_pkcs8_base64, 0, sizeof(char) * private_key_base64_pkcs8_size);

  size_t private_key_base64_pkcs8_len = 0;
  if ((ret = atchops_base64_encode(private_key_pkcs8, 26 + private_key_non_base64_len, private_key_pkcs8_base64,
                                   private_key_base64_pkcs8_size, &private_key_base64_pkcs8_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to encode private key\n");
    goto exit;
  }

  /*
   * 7. Populate the atchops_rsa_key_public_key and atchops_rsa_key_private_key structs
   */

  if ((ret = atchops_rsa_key_populate_public_key(public_key, (const char *)public_key_base64, public_key_base64_len)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate public key\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_populate_private_key(private_key, (const char *)private_key_pkcs8_base64,
                                                  private_key_base64_pkcs8_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate private key\n");
    goto exit;
  }

exit: {
  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  free(private_key_non_base64);
  free(private_key_pkcs8_base64);
  free(private_key_pkcs8);
  return ret;
}
}

int atchops_rsa_key_populate_public_key(atchops_rsa_key_public_key *public_key, const char *public_key_base64,
                                        const size_t public_key_base64_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return ret;
  }

  if (public_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key_base64 is null\n");
    return ret;
  }

  if (public_key_base64_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key_base64_len is less than or equal to 0\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  mbedtls_asn1_sequence *seq = NULL; // free later

  const size_t dst_size = 2048; // sufficient size for a 2048 bit RSA key
  unsigned char dst[dst_size];
  memset(dst, 0, sizeof(unsigned char) * dst_size);
  size_t dst_len = 0;

  if ((ret = atchops_base64_decode((const unsigned char *)public_key_base64, public_key_base64_len, dst, dst_size,
                                   &dst_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
    goto exit;
  }

  unsigned char *p = dst;
  unsigned char *end = dst + dst_len;

  size_t lengthread = 0;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get tag 1\n");
    goto exit;
  }

  size_t lengthread2 = 0;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &lengthread2, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get tag 2\n");
    goto exit;
  }
  p = p + (lengthread2);

  size_t lengthread3 = 0;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &lengthread3, MBEDTLS_ASN1_BIT_STRING)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get tag 3\n");
    goto exit;
  }

  if (*p == 0x00) {
    p = p + 1;
  }

  if ((seq = malloc(sizeof(mbedtls_asn1_sequence))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for seq\n");
    goto exit;
  }
  memset(seq, 0, sizeof(mbedtls_asn1_sequence));
  if ((ret = mbedtls_asn1_get_sequence_of(&p, end, seq, MBEDTLS_ASN1_INTEGER)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get sequence of\n");
    goto exit;
  }

  mbedtls_asn1_sequence *current = seq;
  if ((ret = atchops_rsa_key_public_key_set_n(public_key, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  current = current->next;
  if ((ret = atchops_rsa_key_public_key_set_e(public_key, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set e\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  mbedtls_asn1_sequence_free(seq);
  return ret;
}
}

int atchops_rsa_key_populate_private_key(atchops_rsa_key_private_key *private_key, const char *private_key_base64,
                                         const size_t private_key_base64_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return ret;
  }

  if (private_key_base64 == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key_base64 is null\n");
    return ret;
  }

  if (private_key_base64_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key_base64_len is less than or equal to 0\n");
    return ret;
  }

  /*
   * 2. Variables
   */
  mbedtls_asn1_sequence *seq = NULL; // free later

  const size_t dst_size = 4096; // sufficient size for a 2048 bit RSA private key
  unsigned char dst[dst_size];
  memset(dst, 0, sizeof(unsigned char) * dst_size);
  size_t dst_len = 0;

  if ((ret = atchops_base64_decode((const unsigned char *)private_key_base64, private_key_base64_len, dst, dst_size,
                                   &dst_len)) != 0) {
    goto exit;
  }

  unsigned char *p = dst;
  unsigned char *end = dst + dst_len;

  size_t lengthread = 0;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get tag 1\n");
    goto exit;
  }

  size_t lengthread2 = 0;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &lengthread2, MBEDTLS_ASN1_INTEGER)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get tag 2\n");
    goto exit;
  }
  p = p + lengthread2;

  size_t lengthread3 = 0;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &lengthread3, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get tag 3\n");
    goto exit;
  }
  p = p + lengthread3;

  size_t lengthread4 = 0;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &lengthread4, 0x04)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to get tag 4\n");
    goto exit;
  }

  if ((seq = malloc(sizeof(mbedtls_asn1_sequence))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for seq\n");
    goto exit;
  }
  memset(seq, 0, sizeof(mbedtls_asn1_sequence));
  if ((ret = mbedtls_asn1_get_sequence_of(&p, end, seq, MBEDTLS_ASN1_INTEGER)) != 0) {
    goto exit;
  }

  mbedtls_asn1_sequence *current = seq;
  current = current->next;

  if ((ret = atchops_rsa_key_private_key_set_n(private_key, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  current = current->next;
  if ((ret = atchops_rsa_key_private_key_set_e(private_key, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  current = current->next;
  if ((ret = atchops_rsa_key_private_key_set_d(private_key, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  current = current->next;
  if ((ret = atchops_rsa_key_private_key_set_p(private_key, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  current = current->next;
  if ((ret = atchops_rsa_key_private_key_set_q(private_key, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  mbedtls_asn1_sequence_free(seq);
  return ret;
}
}

bool atchops_rsa_key_is_public_key_populated(const atchops_rsa_key_public_key *public_key) {
  return atchops_rsa_key_public_key_is_n_initialized(public_key) &&
         atchops_rsa_key_public_key_is_e_initialized(public_key);
}

bool atchops_rsa_key_is_private_key_populated(const atchops_rsa_key_private_key *private_key) {
  return atchops_rsa_key_private_key_is_n_initialized(private_key) &&
         atchops_rsa_key_private_key_is_e_initialized(private_key) &&
         atchops_rsa_key_private_key_is_d_initialized(private_key) &&
         atchops_rsa_key_private_key_is_p_initialized(private_key) &&
         atchops_rsa_key_private_key_is_q_initialized(private_key);
}

int atchops_rsa_key_public_key_set_ne(atchops_rsa_key_public_key *public_key, const unsigned char *n,
                                      const size_t n_len, const unsigned char *e, const size_t e_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return ret;
  }

  if (n == NULL || n_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "n is null or n_len is less than or equal to 0\n");
    return ret;
  }

  if (e == NULL || e_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "e is null or e_len is less than or equal to 0\n");
    return ret;
  }

  /*
   * 2. Set the key
   */
  if ((ret = atchops_rsa_key_public_key_set_n(public_key, n, n_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_public_key_set_e(public_key, e, e_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set e\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

bool atchops_rsa_key_public_key_is_n_initialized(const atchops_rsa_key_public_key *public_key) {
  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    return false;
  }

  /*
   * 2. Check if n is initialized
   */
  return public_key->n._is_value_initialized;
}

void atchops_rsa_key_public_key_set_n_initialized(atchops_rsa_key_public_key *public_key, const bool is_initialized) {
  public_key->n._is_value_initialized = is_initialized;
}

int atchops_rsa_key_public_key_set_n(atchops_rsa_key_public_key *public_key, const unsigned char *n,
                                     const size_t n_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return ret;
  }

  if (n == NULL || n_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "n is null or n_len is less than or equal to 0\n");
    return ret;
  }

  /*
   * 2. Set the key
   */
  if (atchops_rsa_key_public_key_is_n_initialized(public_key)) {
    atchops_rsa_key_public_key_unset_n(public_key);
  }

  public_key->n.len = n_len;

  if ((public_key->n.value = (unsigned char *)malloc(sizeof(unsigned char) * (public_key->n.len))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for n value\n");
    goto exit;
  }

  atchops_rsa_key_public_key_set_n_initialized(public_key, true);
  memcpy(public_key->n.value, n, n_len);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsa_key_public_key_unset_n(atchops_rsa_key_public_key *public_key) {
  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return;
  }

  /*
   * 2. Unset the key
   */
  if (atchops_rsa_key_public_key_is_n_initialized(public_key)) {
    free(public_key->n.value);
  }
  atchops_rsa_key_public_key_set_n_initialized(public_key, false);
  public_key->n.value = NULL;
  public_key->n.len = 0;
}

bool atchops_rsa_key_public_key_is_e_initialized(const atchops_rsa_key_public_key *public_key) {
  return public_key->e._is_value_initialized;
}

void atchops_rsa_key_public_key_set_e_initialized(atchops_rsa_key_public_key *public_key, const bool is_initialized) {
  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return;
  }

  /*
   * 2. Set the key
   */
  public_key->e._is_value_initialized = is_initialized;
}

int atchops_rsa_key_public_key_set_e(atchops_rsa_key_public_key *public_key, const unsigned char *e,
                                     const size_t e_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (public_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "public_key is null\n");
    return ret;
  }

  if (e == NULL || e_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "e is null or e_len is less than or equal to 0\n");
    goto exit;
  }

  /*
   * 2. Set the key
   */

  if (atchops_rsa_key_public_key_is_e_initialized(public_key)) {
    atchops_rsa_key_public_key_unset_e(public_key);
  }

  public_key->e.len = e_len;
  if ((public_key->e.value = (unsigned char *)malloc(sizeof(unsigned char) * (public_key->e.len))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for e value\n");
    goto exit;
  }

  atchops_rsa_key_public_key_set_e_initialized(public_key, true);
  memcpy(public_key->e.value, e, e_len);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsa_key_public_key_unset_e(atchops_rsa_key_public_key *public_key) {
  if (atchops_rsa_key_public_key_is_e_initialized(public_key)) {
    free(public_key->e.value);
  }
  atchops_rsa_key_public_key_set_e_initialized(public_key, false);
  public_key->e.value = NULL;
  public_key->e.len = 0;
}

int atchops_rsa_key_private_key_set_nedpq(atchops_rsa_key_private_key *private_key, const unsigned char *n,
                                          const size_t n_len, const unsigned char *e, const size_t e_len,
                                          const unsigned char *d, const size_t d_len, const unsigned char *p,
                                          const size_t p_len, const unsigned char *q, const size_t q_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return ret;
  }

  if (n == NULL || n_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "n is null or n_len is less than or equal to 0\n");
    return ret;
  }

  if (e == NULL || e_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "e is null or e_len is less than or equal to 0\n");
    return ret;
  }

  if (d == NULL || d_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "d is null or d_len is less than or equal to 0\n");
    return ret;
  }

  if (p == NULL || p_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "p is null or p_len is less than or equal to 0\n");
    return ret;
  }

  if (q == NULL || q_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "q is null or q_len is less than or equal to 0\n");
    return ret;
  }

  /*
   * 2. Set the key
   */
  if ((ret = atchops_rsa_key_private_key_set_n(private_key, n, n_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_private_key_set_e(private_key, e, e_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set e\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_private_key_set_d(private_key, d, d_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set d\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_private_key_set_p(private_key, p, p_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set p\n");
    goto exit;
  }

  if ((ret = atchops_rsa_key_private_key_set_q(private_key, q, q_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set q\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

bool atchops_rsa_key_private_key_is_n_initialized(const atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    return false;
  }

  /*
   * 2. Check if n is initialized
   */
  return private_key->n._is_value_initialized;
}

void atchops_rsa_key_private_key_set_n_initialized(atchops_rsa_key_private_key *private_key,
                                                   const bool is_initialized) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Set the value
   */
  private_key->n._is_value_initialized = is_initialized;
}

int atchops_rsa_key_private_key_set_n(atchops_rsa_key_private_key *private_key, const unsigned char *n,
                                      const size_t n_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */

  if (private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return ret;
  }

  if (n == NULL || n_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "n is null or n_len is less than or equal to 0\n");
    return ret;
  }

  /*
   * 2. Set the key
   */
  if (atchops_rsa_key_private_key_is_n_initialized(private_key)) {
    atchops_rsa_key_private_key_unset_n(private_key);
  }

  private_key->n.len = n_len;
  if ((private_key->n.value = (unsigned char *)malloc(sizeof(unsigned char) * (private_key->n.len))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for n value\n");
    goto exit;
  }

  atchops_rsa_key_private_key_set_n_initialized(private_key, true);
  memcpy(private_key->n.value, n, n_len);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsa_key_private_key_unset_n(atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Unset the key
   */
  if (atchops_rsa_key_private_key_is_n_initialized(private_key)) {
    free(private_key->n.value);
  }
  atchops_rsa_key_private_key_set_n_initialized(private_key, false);
  private_key->n.value = NULL;
  private_key->n.len = 0;
}

bool atchops_rsa_key_private_key_is_e_initialized(const atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    return false;
  }
  return private_key->e._is_value_initialized;
}

void atchops_rsa_key_private_key_set_e_initialized(atchops_rsa_key_private_key *private_key,
                                                   const bool is_initialized) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Set the value
   */
  private_key->e._is_value_initialized = is_initialized;
}

int atchops_rsa_key_private_key_set_e(atchops_rsa_key_private_key *private_key, const unsigned char *e,
                                      const size_t e_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */

  if (private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    goto exit;
  }

  if (e == NULL || e_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "e is null or e_len is less than or equal to 0\n");
    goto exit;
  }

  /*
   * 2. Set the key
   */

  if (private_key->e._is_value_initialized) {
    atchops_rsa_key_private_key_unset_e(private_key);
  }

  private_key->e.len = e_len;

  if ((private_key->e.value = (unsigned char *)malloc(sizeof(unsigned char) * (private_key->e.len))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for e value\n");
    goto exit;
  }

  atchops_rsa_key_private_key_set_e_initialized(private_key, true);
  memcpy(private_key->e.value, e, e_len);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsa_key_private_key_unset_e(atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Unset the key
   */
  if (atchops_rsa_key_private_key_is_e_initialized(private_key)) {
    free(private_key->e.value);
  }
  atchops_rsa_key_private_key_set_e_initialized(private_key, false);
  private_key->e.value = NULL;
  private_key->e.len = 0;
}

bool atchops_rsa_key_private_key_is_d_initialized(const atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    return false;
  }

  /*
   * 2. Check if d is initialized
   */
  return private_key->d._is_value_initialized;
}

void atchops_rsa_key_private_key_set_d_initialized(atchops_rsa_key_private_key *private_key,
                                                   const bool is_initialized) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Set the value
   */
  private_key->d._is_value_initialized = is_initialized;
}

int atchops_rsa_key_private_key_set_d(atchops_rsa_key_private_key *private_key, const unsigned char *d,
                                      const size_t d_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    goto exit;
  }

  if (d == NULL || d_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "d is null or d_len is less than or equal to 0\n");
    goto exit;
  }

  /*
   * 2. Set the key
   */
  if (atchops_rsa_key_private_key_is_d_initialized(private_key)) {
    atchops_rsa_key_private_key_unset_d(private_key);
  }

  private_key->d.len = d_len;

  if ((private_key->d.value = (unsigned char *)malloc(sizeof(unsigned char) * (private_key->d.len))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for d value\n");
    goto exit;
  }

  atchops_rsa_key_private_key_set_d_initialized(private_key, true);
  memcpy(private_key->d.value, d, d_len);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsa_key_private_key_unset_d(atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Unset the key
   */
  if (atchops_rsa_key_private_key_is_d_initialized(private_key)) {
    free(private_key->d.value);
  }
  atchops_rsa_key_private_key_set_d_initialized(private_key, false);
  private_key->d.value = NULL;
  private_key->d.len = 0;
}

bool atchops_rsa_key_private_key_is_p_initialized(const atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    return false;
  }

  /*
   * 2. Check if p is initialized
   */
  return private_key->p._is_value_initialized;
}

void atchops_rsa_key_private_key_set_p_initialized(atchops_rsa_key_private_key *private_key,
                                                   const bool is_initialized) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Set the value
   */
  private_key->p._is_value_initialized = is_initialized;
}

int atchops_rsa_key_private_key_set_p(atchops_rsa_key_private_key *private_key, const unsigned char *p,
                                      const size_t p_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    goto exit;
  }

  if (p == NULL || p_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "p is null or p_len is less than or equal to 0\n");
    goto exit;
  }

  /*
   * 2. Set the key
   */
  if (atchops_rsa_key_private_key_is_p_initialized(private_key)) {
    atchops_rsa_key_private_key_unset_p(private_key);
  }

  private_key->p.len = p_len;

  private_key->p.value = (unsigned char *)malloc(sizeof(unsigned char) * (private_key->p.len));
  if (private_key->p.value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for p value\n");
    goto exit;
  }

  atchops_rsa_key_private_key_set_p_initialized(private_key, true);
  memcpy(private_key->p.value, p, p_len);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsa_key_private_key_unset_p(atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Unset the key
   */
  if (atchops_rsa_key_private_key_is_p_initialized(private_key)) {
    free(private_key->p.value);
  }
  atchops_rsa_key_private_key_set_p_initialized(private_key, false);
  private_key->p.value = NULL;
  private_key->p.len = 0;
}

bool atchops_rsa_key_private_key_is_q_initialized(const atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    return false;
  }

  /*
   * 2. Check if q is initialized
   */
  return private_key->q._is_value_initialized;
}

void atchops_rsa_key_private_key_set_q_initialized(atchops_rsa_key_private_key *private_key,
                                                   const bool is_initialized) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Set the value
   */
  private_key->q._is_value_initialized = is_initialized;
}

int atchops_rsa_key_private_key_set_q(atchops_rsa_key_private_key *private_key, const unsigned char *q,
                                      const size_t q_len) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    goto exit;
  }

  if (q == NULL || q_len <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "q is null or q_len is less than or equal to 0\n");
    goto exit;
  }

  /*
   * 2. Set the key
   */
  if (atchops_rsa_key_private_key_is_q_initialized(private_key)) {
    atchops_rsa_key_private_key_unset_q(private_key);
  }

  private_key->q.len = q_len;

  if ((private_key->q.value = (unsigned char *)malloc(sizeof(unsigned char) * (private_key->q.len))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for q value\n");
    goto exit;
  }

  atchops_rsa_key_private_key_set_q_initialized(private_key, true);
  memcpy(private_key->q.value, q, q_len);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsa_key_private_key_unset_q(atchops_rsa_key_private_key *private_key) {
  /*
   * 1. Validate arguments
   */
  if (private_key == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "private_key is null\n");
    return;
  }

  /*
   * 2. Unset the key
   */
  if (atchops_rsa_key_private_key_is_q_initialized(private_key)) {
    free(private_key->q.value);
  }
  atchops_rsa_key_private_key_set_q_initialized(private_key, false);
  private_key->q.value = NULL;
  private_key->q.len = 0;
}
