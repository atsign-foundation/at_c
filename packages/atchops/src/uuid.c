#include "atchops/uuid.h"
#include <atchops/platform.h>
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TAG "uuid"

// uuid4 was originally an external library which was depended upon as
// an external dependency, it has been moved into this file as private
// symbols so that it's easier to make platform specific overrides
// Original repo: https://github.com/rxi/uuid4
// Fork (now merged into here): https://github.com/atsign-foundation/uuid4

// This section is from uuid4/uuid4.h
/**
 * Copyright (c) 2018 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

enum { UUID4_ESUCCESS = 0, UUID4_EFAILURE = -1 };

static int uuid4_init(void);
static void uuid4_generate(char *dst);

#if (__STDC_VERSION__ >= 201112L)
_Thread_local
#endif
    static uint64_t seed[2];

// End of copyright

int atchops_uuid_init(void) { return uuid4_init(); }

int atchops_uuid_generate(char *uuidstr, const size_t uuidstrlen) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (uuidstr == NULL) {
    ret = 1; // UUID buffer is NULL
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "UUID buffer is NULL\n");
    goto exit;
  }

  if (uuidstrlen <= 0) {
    ret = 1; // UUID buffer length is less than or equal to 0
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "UUID buffer length is less than or equal to 0\n");
    goto exit;
  }

  if (uuidstrlen < 37) {
    ret = 1; // UUID string is 36 characters long + 1 for null terminator = 37 minimum buffer length
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "UUID buffer length is less than 37\n");
    goto exit;
  }

  /*
   * 2. Generate UUID
   */
  uuid4_generate(uuidstr);
  if (strlen(uuidstr) <= 0) {
    ret = 1; // an error occurred regarding the UUID generation and writing it to the buffer
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

// This section is from uuid4/uuid4.c with some modifications for broader
// platform support
/**
 * Copyright (c) 2018 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#if defined(ATCHOPS_TARGET_ESPIDF)
#include "esp_random.h"
#else
#include "atchops/mbedtls.h"
#endif

static uint64_t xorshift128plus(uint64_t *s) {
  /* http://xorshift.di.unimi.it/xorshift128plus.c */
  uint64_t s1 = s[0];
  const uint64_t s0 = s[1];
  s[0] = s0;
  s1 ^= s1 << 23;
  s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
  return s[1] + s0;
}

static int uuid4_init(void) {
#if defined(ATCHOPS_TARGET_UNIX) || defined(ATCHOPS_TARGET_WINDOWS) || defined(ATCHOPS_TARGET_ARDUINO)
  int ret = 0;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;

  // TODO replace this string
  const unsigned char pers[13] = {"Arduino_Seed"};

  size_t off = sizeof(uint64_t) / sizeof(unsigned char);
  size_t n = off * 2;
  unsigned char pointer[n]; // create char pointer to long number
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, sizeof(pers));
  if (ret != 0) {
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return UUID4_EFAILURE;
  }
  for (size_t i = 0; i < n; i++) {
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, pointer, n);
    if (ret != 0) {
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
      return UUID4_EFAILURE;
    }
  }
  for (size_t i = 0; i < 2; i++) {
    seed[i] = 0;
    for (size_t j = 0; j < n / 2; j++) {
      seed[i] =
          seed[i] | ((uint64_t)pointer[i * off + j] << j * sizeof(unsigned char) * 4); // 8/2 = 4 - byte to bit offset
    }
  }

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return UUID4_ESUCCESS;
#elif defined(ATCHOPS_TARGET_ESPIDF)
  for (int i = 0; i < 2; i++) {
    seed[i] = ((uint64_t)esp_random() << 32) | esp_random(); // Generate random 64-bit values
  }
#else
#error "unsupported platform"
#endif
  return UUID4_ESUCCESS;
}

static void uuid4_generate(char *dst) {
  static const char *template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
  static const char *chars = "0123456789abcdef";
  union {
    unsigned char b[16];
    uint64_t word[2];
  } s;
  const char *p;
  int i, n;
  /* get random */
  s.word[0] = xorshift128plus(seed);
  s.word[1] = xorshift128plus(seed);
  /* build string */
  p = template;
  i = 0;
  while (*p) {
    n = s.b[i >> 1];
    n = (i & 1) ? (n >> 4) : (n & 0xf);
    switch (*p) {
    case 'x':
      *dst = chars[n];
      i++;
      break;
    case 'y':
      *dst = chars[(n & 0x3) + 8];
      i++;
      break;
    default:
      *dst = *p;
    }
    dst++, p++;
  }
  *dst = '\0';
}

// End of Copyright
