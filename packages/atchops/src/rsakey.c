#include "atchops/rsakey.h"
#include "atchops/base64.h"
#include <mbedtls/asn1.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define BASE64_DECODED_KEY_BUFFER_SIZE 8192 // the max buffer size of a decoded RSA key

void atchops_rsakey_publickey_init(atchops_rsakey_publickey *publickey) {
  memset(publickey, 0, sizeof(atchops_rsakey_publickey));

  publickey->n.len = BASE64_DECODED_KEY_BUFFER_SIZE;
  publickey->n.value = (unsigned char *)malloc(sizeof(unsigned char) * publickey->n.len);

  publickey->e.len = BASE64_DECODED_KEY_BUFFER_SIZE;
  publickey->e.value = (unsigned char *)malloc(sizeof(unsigned char) * publickey->e.len);
}

void atchops_rsakey_publickey_clone(atchops_rsakey_publickey *dst, atchops_rsakey_publickey *src) {
  memset(dst, 0, sizeof(atchops_rsakey_publickey));

  dst->n.len = src->n.len;
  dst->n.value = (unsigned char *)malloc(sizeof(unsigned char) * dst->n.len);
  memcpy(dst->n.value, src->n.value, dst->n.len);

  dst->e.len = src->e.len;
  dst->e.value = (unsigned char *)malloc(sizeof(unsigned char) * dst->e.len);
  memcpy(dst->e.value, src->e.value, dst->e.len);
}

void atchops_rsakey_publickey_free(atchops_rsakey_publickey *publickey) {
  free(publickey->n.value);
  free(publickey->e.value);
}

void atchops_rsakey_privatekey_init(atchops_rsakey_privatekey *privatekey) {
  memset(privatekey, 0, sizeof(atchops_rsakey_privatekey));

  privatekey->n.len = BASE64_DECODED_KEY_BUFFER_SIZE;
  privatekey->n.value = malloc(sizeof(unsigned char) * privatekey->n.len);

  privatekey->e.len = BASE64_DECODED_KEY_BUFFER_SIZE;
  privatekey->e.value = malloc(sizeof(unsigned char) * privatekey->e.len);

  privatekey->d.len = BASE64_DECODED_KEY_BUFFER_SIZE;
  privatekey->d.value = malloc(sizeof(unsigned char) * privatekey->d.len);

  privatekey->p.len = BASE64_DECODED_KEY_BUFFER_SIZE;
  privatekey->p.value = malloc(sizeof(unsigned char) * privatekey->p.len);

  privatekey->q.len = BASE64_DECODED_KEY_BUFFER_SIZE;
  privatekey->q.value = malloc(sizeof(unsigned char) * privatekey->q.len);
}

void atchops_rsakey_privatekey_clone(atchops_rsakey_privatekey *dst, atchops_rsakey_privatekey *src) {
  memset(dst, 0, sizeof(atchops_rsakey_privatekey));
  dst->n.len = src->n.len;
  dst->n.value = (unsigned char *)malloc(sizeof(unsigned char) * dst->n.len);
  memcpy(dst->n.value, src->n.value, dst->n.len);

  dst->e.len = src->e.len;
  dst->e.value = (unsigned char *)malloc(sizeof(unsigned char) * dst->e.len);
  memcpy(dst->e.value, src->e.value, dst->e.len);

  dst->d.len = src->d.len;
  dst->d.value = (unsigned char *)malloc(sizeof(unsigned char) * dst->d.len);
  memcpy(dst->d.value, src->d.value, dst->d.len);

  dst->p.len = src->p.len;
  dst->p.value = (unsigned char *)malloc(sizeof(unsigned char) * dst->p.len);
  memcpy(dst->p.value, src->p.value, dst->p.len);

  dst->q.len = src->q.len;
  dst->q.value = (unsigned char *)malloc(sizeof(unsigned char) * dst->q.len);
  memcpy(dst->q.value, src->q.value, dst->q.len);
}

void atchops_rsakey_privatekey_free(atchops_rsakey_privatekey *privatekey) {
  free(privatekey->n.value);
  free(privatekey->e.value);
  free(privatekey->d.value);
  free(privatekey->p.value);
  free(privatekey->q.value);
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
  memset(seq, 0, sizeof(mbedtls_asn1_sequence));
  ret = mbedtls_asn1_get_sequence_of(&p, end, seq, MBEDTLS_ASN1_INTEGER);
  if (ret != 0) {
    goto exit;
  }

  mbedtls_asn1_sequence *current = seq;
  current = current->next;

  privatekey->n.len = current->buf.len;
  memcpy(privatekey->n.value, current->buf.p, privatekey->n.len);

  current = current->next;
  privatekey->e.len = current->buf.len;
  memcpy(privatekey->e.value, current->buf.p, privatekey->e.len);

  current = current->next;
  privatekey->d.len = current->buf.len;
  memcpy(privatekey->d.value, current->buf.p, privatekey->d.len);

  current = current->next;
  privatekey->p.len = current->buf.len;
  memcpy(privatekey->p.value, current->buf.p, privatekey->p.len);

  current = current->next;
  privatekey->q.len = current->buf.len;
  memcpy(privatekey->q.value, current->buf.p, privatekey->q.len);

  ret = 0;
  goto exit;
exit: {
  mbedtls_asn1_sequence_free(seq);
  return ret;
}
}
