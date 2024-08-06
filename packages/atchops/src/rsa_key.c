#include "atchops/rsa_key.h"
#include "atchops/base64.h"
#include "atchops/mbedtls.h"
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "rsa_key"

#define BASE64_DECODED_KEY_BUFFER_SIZE 8192 // the max buffer size of a decoded RSA key

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

  const size_t dst_size = BASE64_DECODED_KEY_BUFFER_SIZE;
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

  const size_t dst_size = BASE64_DECODED_KEY_BUFFER_SIZE;
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
  return atchops_rsa_key_public_key_is_n_initialized(public_key) && atchops_rsa_key_public_key_is_e_initialized(public_key);
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

bool atchops_rsa_key_public_key_is_n_initialized(atchops_rsa_key_public_key *public_key) {
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

bool atchops_rsa_key_public_key_is_e_initialized(atchops_rsa_key_public_key *public_key) {
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

bool atchops_rsa_key_private_key_is_n_initialized(atchops_rsa_key_private_key *private_key) {
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

bool atchops_rsa_key_private_key_is_e_initialized(atchops_rsa_key_private_key *private_key) {
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

bool atchops_rsa_key_private_key_is_d_initialized(atchops_rsa_key_private_key *private_key) {
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

bool atchops_rsa_key_private_key_is_p_initialized(atchops_rsa_key_private_key *private_key) {
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

bool atchops_rsa_key_private_key_is_q_initialized(atchops_rsa_key_private_key *private_key) {
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

void atchops_rsa_key_private_key_set_q_initialized(atchops_rsa_key_private_key *private_key, const bool is_initialized) {
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

  if ((private_key->q.value = (unsigned char *)malloc(sizeof(unsigned char) * q_len)) == NULL) {
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
