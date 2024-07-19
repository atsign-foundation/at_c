#include "atchops/rsakey.h"
#include "atchops/base64.h"
#include <atlogger/atlogger.h>
#include <mbedtls/asn1.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define BASE64_DECODED_KEY_BUFFER_SIZE 8192 // the max buffer size of a decoded RSA key

#define TAG "rsakey"

void atchops_rsakey_publickey_init(atchops_rsakey_publickey *publickey) {
  memset(publickey, 0, sizeof(atchops_rsakey_publickey));
}

void atchops_rsakey_publickey_free(atchops_rsakey_publickey *publickey) {
  atchops_rsakey_publickey_unset_n(publickey);
  atchops_rsakey_publickey_unset_e(publickey);
  memset(publickey, 0, sizeof(atchops_rsakey_publickey));
}

void atchops_rsakey_privatekey_init(atchops_rsakey_privatekey *privatekey) {
  memset(privatekey, 0, sizeof(atchops_rsakey_privatekey));
}

void atchops_rsakey_privatekey_free(atchops_rsakey_privatekey *privatekey) {
  atchops_rsakey_privatekey_unset_n(privatekey);
  atchops_rsakey_privatekey_unset_e(privatekey);
  atchops_rsakey_privatekey_unset_d(privatekey);
  atchops_rsakey_privatekey_unset_p(privatekey);
  atchops_rsakey_privatekey_unset_q(privatekey);
  memset(privatekey, 0, sizeof(atchops_rsakey_privatekey));
}

int atchops_rsakey_publickey_clone(const atchops_rsakey_publickey *src, atchops_rsakey_publickey *dst) {
  int ret = 1;

  if ((ret = atchops_rsakey_publickey_set_n(dst, src->n.value, src->n.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  if ((ret = atchops_rsakey_publickey_set_e(dst, src->e.value, src->e.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set e\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atchops_rsakey_privatekey_clone(const atchops_rsakey_privatekey *src, atchops_rsakey_privatekey *dst) {
  int ret = 1;

  if ((ret = atchops_rsakey_privatekey_set_n(dst, src->n.value, src->n.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  if ((ret = atchops_rsakey_privatekey_set_e(dst, src->e.value, src->e.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set e\n");
    goto exit;
  }

  if ((ret = atchops_rsakey_privatekey_set_d(dst, src->d.value, src->d.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set d\n");
    goto exit;
  }

  if ((ret = atchops_rsakey_privatekey_set_p(dst, src->p.value, src->p.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set p\n");
    goto exit;
  }

  if ((ret = atchops_rsakey_privatekey_set_q(dst, src->q.value, src->q.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set q\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

int atchops_rsakey_populate_publickey(atchops_rsakey_publickey *publickey, const char *publickeybase64,
                                      const size_t publickeybase64len) {
  int ret = 0;

  mbedtls_asn1_sequence *seq = NULL; // free later

  size_t dstsize = BASE64_DECODED_KEY_BUFFER_SIZE;
  unsigned char dst[dstsize];
  memset(dst, 0, sizeof(unsigned char) * dstsize);
  size_t dstlen = 0;
  ret = atchops_base64_decode((const unsigned char *)publickeybase64, publickeybase64len, dst, dstsize, &dstlen);
  if (ret != 0) {
    goto exit;
  }

  unsigned char *p = dst;
  unsigned char *end = dst + dstlen;

  size_t lengthread = 0;
  ret = mbedtls_asn1_get_tag(&p, end, &lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (ret != 0) {
    goto exit;
  }

  size_t lengthread2 = 0;
  ret = mbedtls_asn1_get_tag(&p, end, &lengthread2, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (ret != 0) {
    goto exit;
  }
  p = p + (lengthread2);

  size_t lengthread3 = 0;
  ret = mbedtls_asn1_get_tag(&p, end, &lengthread3, MBEDTLS_ASN1_BIT_STRING);
  if (ret != 0) {
    goto exit;
  }

  if (*p == 0x00) {
    p = p + 1;
  }

  seq = malloc(sizeof(mbedtls_asn1_sequence));
  if (seq == NULL) {
    ret = 1;
    goto exit;
  }
  memset(seq, 0, sizeof(mbedtls_asn1_sequence));
  ret = mbedtls_asn1_get_sequence_of(&p, end, seq, MBEDTLS_ASN1_INTEGER);
  if (ret != 0) {
    goto exit;
  }

  mbedtls_asn1_sequence *current = seq;
  publickey->n.len = current->buf.len;
  memcpy(publickey->n.value, current->buf.p, publickey->n.len);

  current = current->next;
  publickey->e.len = current->buf.len;
  memcpy(publickey->e.value, current->buf.p, publickey->e.len);

  ret = 0;
  goto exit;
exit: {
  mbedtls_asn1_sequence_free(seq);
  return ret;
}
}

int atchops_rsakey_populate_privatekey(atchops_rsakey_privatekey *privatekey, const char *privatekeybase64,
                                       const size_t privatekeybase64len) {
  int ret = 1;

  mbedtls_asn1_sequence *seq = NULL; // free later

  const size_t dstsize = BASE64_DECODED_KEY_BUFFER_SIZE;
  unsigned char dst[dstsize];
  memset(dst, 0, sizeof(unsigned char) * dstsize);
  size_t dstlen = 0;
  ret = atchops_base64_decode((const unsigned char *)privatekeybase64, privatekeybase64len, dst, dstsize, &dstlen);
  if (ret != 0) {
    goto exit;
  }

  unsigned char *p = dst;
  unsigned char *end = dst + dstlen;

  size_t lengthread = 0;
  ret = mbedtls_asn1_get_tag(&p, end, &lengthread, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (ret != 0) {
    goto exit;
  }

  size_t lengthread2 = 0;
  ret = mbedtls_asn1_get_tag(&p, end, &lengthread2, MBEDTLS_ASN1_INTEGER);
  if (ret != 0) {
    goto exit;
  }
  p = p + lengthread2;

  size_t lengthread3 = 0;
  ret = mbedtls_asn1_get_tag(&p, end, &lengthread3, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
  if (ret != 0) {
    goto exit;
  }
  p = p + lengthread3;

  size_t lengthread4 = 0;
  ret = mbedtls_asn1_get_tag(&p, end, &lengthread4, 0x04);
  if (ret != 0) {
    goto exit;
  }

  seq = malloc(sizeof(mbedtls_asn1_sequence));
  if (seq == NULL) {
    ret = 1;
    goto exit;
  }
  memset(seq, 0, sizeof(mbedtls_asn1_sequence));
  ret = mbedtls_asn1_get_sequence_of(&p, end, seq, MBEDTLS_ASN1_INTEGER);
  if (ret != 0) {
    goto exit;
  }

  mbedtls_asn1_sequence *current = seq;
  current = current->next;

  if ((ret = atchops_rsakey_privatekey_set_n(privatekey, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  current = current->next;
  if ((ret = atchops_rsakey_privatekey_set_e(privatekey, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  current = current->next;
  if ((ret = atchops_rsakey_privatekey_set_d(privatekey, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  current = current->next;
  if ((ret = atchops_rsakey_privatekey_set_p(privatekey, current->buf.p, current->buf.len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  current = current->next;
  if ((ret = atchops_rsakey_privatekey_set_q(privatekey, current->buf.p, current->buf.len)) != 0) {
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

int atchops_rsakey_publickey_set_ne(atchops_rsakey_publickey *publickey, const unsigned char *n, const size_t nlen,
                                    const unsigned char *e, const size_t elen) {
  int ret = 1;

  if ((ret = atchops_rsakey_publickey_set_n(publickey, n, nlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  if ((ret = atchops_rsakey_publickey_set_e(publickey, e, elen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set e\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

bool atchops_rsakey_publickey_is_n_initialized(atchops_rsakey_publickey *publickey) {
  return publickey->n._is_value_initialized;
}

int atchops_rsakey_publickey_set_n(atchops_rsakey_publickey *publickey, const unsigned char *n, const size_t nlen) {
  int ret = 1;
  if (n == NULL || nlen <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "n is null or nlen is less than or equal to 0\n");
    goto exit;
  }

  atchops_rsakey_publickey_unset_n(publickey);

  publickey->n.len = nlen;

  publickey->n.value = (unsigned char *)malloc(sizeof(unsigned char) * (publickey->n.len));
  if (publickey->n.value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for n value\n");
    goto exit;
  }

  publickey->n._is_value_initialized = true;
  memcpy(publickey->n.value, n, nlen);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsakey_publickey_unset_n(atchops_rsakey_publickey *publickey) {
  if (publickey->n._is_value_initialized) {
    free(publickey->n.value);
  }
  publickey->n._is_value_initialized = false;
  publickey->n.value = NULL;
  publickey->n.len = 0;
}

bool atchops_rsakey_publickey_is_e_initialized(atchops_rsakey_publickey *publickey) {
  return publickey->e._is_value_initialized;
}

int atchops_rsakey_publickey_set_e(atchops_rsakey_publickey *publickey, const unsigned char *e, const size_t elen) {
  int ret = 1;
  if (e == NULL || elen <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "e is null or elen is less than or equal to 0\n");
    goto exit;
  }

  atchops_rsakey_publickey_unset_e(publickey);

  publickey->e.len = elen;

  publickey->e.value = (unsigned char *)malloc(sizeof(unsigned char) * (publickey->e.len));
  if (publickey->e.value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for e value\n");
    goto exit;
  }

  publickey->e._is_value_initialized = true;
  memcpy(publickey->e.value, e, elen);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsakey_publickey_unset_e(atchops_rsakey_publickey *publickey) {
  if (publickey->e._is_value_initialized) {
    free(publickey->e.value);
  }
  publickey->e._is_value_initialized = false;
  publickey->e.value = NULL;
  publickey->e.len = 0;
}

int atchops_rsakey_privatekey_set_nedpq(atchops_rsakey_privatekey *privatekey, const unsigned char *n,
                                        const size_t nlen, const unsigned char *e, const size_t elen,
                                        const unsigned char *d, const size_t dlen, const unsigned char *p,
                                        const size_t plen, const unsigned char *q, const size_t qlen) {
  int ret = 1;

  if ((ret = atchops_rsakey_privatekey_set_n(privatekey, n, nlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set n\n");
    goto exit;
  }

  if ((ret = atchops_rsakey_privatekey_set_e(privatekey, e, elen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set e\n");
    goto exit;
  }

  if ((ret = atchops_rsakey_privatekey_set_d(privatekey, d, dlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set d\n");
    goto exit;
  }

  if ((ret = atchops_rsakey_privatekey_set_p(privatekey, p, plen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set p\n");
    goto exit;
  }

  if ((ret = atchops_rsakey_privatekey_set_q(privatekey, q, qlen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set q\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

bool atchops_rsakey_privatekey_is_n_initialized(atchops_rsakey_privatekey *privatekey) {
  return privatekey->n._is_value_initialized;
}

int atchops_rsakey_privatekey_set_n(atchops_rsakey_privatekey *privatekey, const unsigned char *n, const size_t nlen) {
  int ret = 1;

  if (n == NULL || nlen <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "n is null or nlen is less than or equal to 0\n");
    goto exit;
  }

  atchops_rsakey_privatekey_unset_n(privatekey);

  privatekey->n.len = nlen;

  privatekey->n.value = (unsigned char *)malloc(sizeof(unsigned char) * (privatekey->n.len));
  if (privatekey->n.value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for n value\n");
    goto exit;
  }

  privatekey->n._is_value_initialized = true;
  memcpy(privatekey->n.value, n, nlen);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsakey_privatekey_unset_n(atchops_rsakey_privatekey *privatekey) {
  if (privatekey->n._is_value_initialized) {
    free(privatekey->n.value);
  }
  privatekey->n._is_value_initialized = false;
  privatekey->n.value = NULL;
  privatekey->n.len = 0;
}

bool atchops_rsakey_privatekey_is_e_initialized(atchops_rsakey_privatekey *privatekey) {
  return privatekey->e._is_value_initialized;
}

int atchops_rsakey_privatekey_set_e(atchops_rsakey_privatekey *privatekey, const unsigned char *e, const size_t elen) {
  int ret = 1;

  if (e == NULL || elen <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "e is null or elen is less than or equal to 0\n");
    goto exit;
  }

  atchops_rsakey_privatekey_unset_e(privatekey);

  privatekey->e.len = elen;

  privatekey->e.value = (unsigned char *)malloc(sizeof(unsigned char) * (privatekey->e.len));
  if (privatekey->e.value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for e value\n");
    goto exit;
  }

  privatekey->e._is_value_initialized = true;
  memcpy(privatekey->e.value, e, elen);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsakey_privatekey_unset_e(atchops_rsakey_privatekey *privatekey) {
  if (privatekey->e._is_value_initialized) {
    free(privatekey->e.value);
  }
  privatekey->e.value = NULL;
  privatekey->e.len = 0;
  privatekey->e._is_value_initialized = false;
}

bool atchops_rsakey_privatekey_is_d_initialized(atchops_rsakey_privatekey *privatekey) {
  return privatekey->d._is_value_initialized;
}

int atchops_rsakey_privatekey_set_d(atchops_rsakey_privatekey *privatekey, const unsigned char *d, const size_t dlen) {
  int ret = 1;

  if (d == NULL || dlen <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "d is null or dlen is less than or equal to 0\n");
    goto exit;
  }

  atchops_rsakey_privatekey_unset_d(privatekey);

  privatekey->d.len = dlen;

  privatekey->d.value = (unsigned char *)malloc(sizeof(unsigned char) * (privatekey->d.len));
  if (privatekey->d.value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for d value\n");
    goto exit;
  }

  privatekey->d._is_value_initialized = true;
  memcpy(privatekey->d.value, d, dlen);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsakey_privatekey_unset_d(atchops_rsakey_privatekey *privatekey) {
  if (privatekey->d._is_value_initialized) {
    free(privatekey->d.value);
  }
  privatekey->d._is_value_initialized = false;
  privatekey->d.value = NULL;
  privatekey->d.len = 0;
}

bool atchops_rsakey_privatekey_is_p_initialized(atchops_rsakey_privatekey *privatekey) {
  return privatekey->p._is_value_initialized;
}

int atchops_rsakey_privatekey_set_p(atchops_rsakey_privatekey *privatekey, const unsigned char *p, const size_t plen) {
  int ret = 1;

  if (p == NULL || plen <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "p is null or plen is less than or equal to 0\n");
    goto exit;
  }

  atchops_rsakey_privatekey_unset_p(privatekey);

  privatekey->p.len = plen;

  privatekey->p.value = (unsigned char *)malloc(sizeof(unsigned char) * (privatekey->p.len));
  if (privatekey->p.value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for p value\n");
    goto exit;
  }

  privatekey->p._is_value_initialized = true;
  memcpy(privatekey->p.value, p, plen);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsakey_privatekey_unset_p(atchops_rsakey_privatekey *privatekey) {
  if (privatekey->p._is_value_initialized) {
    free(privatekey->p.value);
  }
  privatekey->p._is_value_initialized = false;
  privatekey->p.value = NULL;
  privatekey->p.len = 0;
}

bool atchops_rsakey_privatekey_is_q_initialized(atchops_rsakey_privatekey *privatekey) {
  return privatekey->q._is_value_initialized;
}

int atchops_rsakey_privatekey_set_q(atchops_rsakey_privatekey *privatekey, const unsigned char *q, const size_t qlen) {
  int ret = 1;

  if (q == NULL || qlen <= 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "q is null or qlen is less than or equal to 0\n");
    goto exit;
  }

  atchops_rsakey_privatekey_unset_q(privatekey);

  privatekey->q.len = qlen;

  privatekey->q.value = (unsigned char *)malloc(sizeof(unsigned char) * qlen);
  if (privatekey->q.value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for q value\n");
    goto exit;
  }

  privatekey->q._is_value_initialized = true;
  memcpy(privatekey->q.value, q, qlen);

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atchops_rsakey_privatekey_unset_q(atchops_rsakey_privatekey *privatekey) {
  if (privatekey->q._is_value_initialized) {
    free(privatekey->q.value);
  }
  privatekey->q.value = NULL;
  privatekey->q.len = 0;
  privatekey->q._is_value_initialized = false;
}
