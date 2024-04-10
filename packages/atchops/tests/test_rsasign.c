#include "atchops/rsa.h"
#include <mbedtls/md.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define PRIVATE_KEY_BASE64                                                                                             \
  "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCy64Pzy9ZDdm6e96z3DmjektD7sKUo40Ax+"                              \
  "1VD12Ksm3pUPTGDkM3Nf4Sp2ATcy6ZbCRHSEWtx7dPfC/H1p7yS9KOVLtAmx8aT0SNiT+WGsclshI/n/XP+jCjxrpYwf4ntgX2i6p6hlo/"         \
  "ZiW8i3+Ayyhw8uYuVMUyMHv70EaoTN0+N5QF9l74LkLYL7cXyfZayDPTZJxbLF2WEoQz4ZWJhgFk40EeBw03jiLg/T0hw1gbS0z97HhZs/"         \
  "QPtTaDR9EJYq27eZagRFZ6em7esrjjTpmGaTJmtZjEomV6o/EOtdvImRe1tViI22DWGAKi87BBGXR5Zr3xoRXPSypHLqLsNAgMBAAECggEAatzd//"  \
  "QEMmD/KzVU+m6B1kYsSde0nZo1kmTCBXYUenGWe8/cze7j7NQ4AVWDefiskHz3Rteeq/pXbEXvK0EXEVLKjWTbb/"                           \
  "4sLcdg8ew0c+GmI4l9hhtMd4FxRwB2tdrHH7MSvgaR3oNVwaEjXtoGR2+Ns/"                                                       \
  "tCUkaSqLIupsoSIc0Mj07Teq7SZvAe++oMyNgkyArR509oSG0GQFQp706VgLaUVrvtlMEXvtGB0pcn/y1Axz/"                              \
  "l9VvYpojYp7MqSwVU6R4GWxjrn4JXCVQrh48VmuJS83i2oqFgbAXD2KyNjjkoW3Z26uhfJ0qgN2PeQgMYH06gNhfEYOAGTI8HgtfChQKBgQDc7xIYG" \
  "0IchAX/0lds4yUXRRF9wEjZmsvaf6LZPEs97/z11cAbTp41zlppCqpGL0md/"                                                       \
  "lTwFVwsmGuZNob999sGKi7A6mM2sBj+"                                                                                    \
  "QiBoHACvl2e167O72eFYqyXtJwDH5XOA5JMHbc6GJpSeVE29UnIgq1czgp3DtapQRX3BOPMRYwKBgQDPUVjZJERK5N9ccs59gjyKiu6e60m42AVjpv" \
  "aCWbqPSZXTEhGM8X9OJNsdZufRoMi6tYctXGthiB4HOoV1E5ACvJxgWpOTmbqqbBDA5pQPrJ4eRdigHjGnrAWdsJ+3smMbhk/"                  \
  "6Ai00gmqwz8rv7eyGSY+dwOem/vPoJOrlRFFkzwKBgH+IhbJiscQSNgBZpFvXtwZ6uUEU6Tir0bccbJ3n3ysuyKAENnPM6yj2KFxwaqA/"          \
  "FcjdEpzQR7f6eEomHsCl/cnOOdTkuEbOWm8TLu/KEl9KD/"                                                                     \
  "UEzWjHufxcN3VxSVMa0ZT63SCxs0DfLnVDBukdmYHgRmMWqAlcaacSpigOvskvAoGADVikSp5OEzA2vOHbLzNCKH0XLX3iKhcmCatG9U9Hdk/"      \
  "7aDIilRs64dH3lSX5yIH8SiDDigUIGKhFnpuC2e2feL2hp4ZNN9ROswfv8Csn3vZy22oNrwkikzO8zNEBBzdhr/"                            \
  "Tukx6uwFGhAq7t1pJPhrmXmEVB5HtHQmuV/"                                                                                \
  "5ptTvsCgYA5d5L3hO3+1Na4C6xj8luQXFhkSLNe0rwoe16OLjcyzcnhlb2KKA8rORGP28s1JcCL4Htasf0YzCkOJ/jR28GzX/"                  \
  "0qvWu0hBSilV2mCAqwQ1fvZx0L4quJznkAhJPMZ+oag8o1LlQiJGgnhsIMbDLZApKh3NuYlTmdqo20FfkZkg=="

#define SIGNATURE_BUFFER_LEN 5000

#define MESSAGE "_4a160d33-0c63-4800-bee0-ee254752f8c8@jeremy_0:6c987cc1-0dde-4ba1-af56-a9677086182"

// #define EXPECTED_SIGNATURE
// "qaEysA8nF/aGjXiIqtHZzZbM90+fn2Ugpy5hgBf0izPoBR2orbeWVUJ1sI5fNMkMwOziRjA6j+AKcG4O/NaLYd31WOq4QzxDqRV+AY4d04mBZsa9wDd/30hSeUwCmubFNrHNSXi84HJS3D886FdByp2wRee5DIu6CalF4yCCpXO5YeTNNFvbk8Spqz3GY4cvjWhVW1ISBfQ928dWTuOkTfqiv/2cj9VAb460EoPeeWYabX1J2SBqUjRWsQsjiOiGiRYcft0DRc5TBru/oVGFrxbB+VL+HGc0Boi1T23FPoyg5FazF0yK2BBW0PWUqQ0BDny/1tZg7p8Wtv8ERHhxew="
#define EXPECTED_SIGNATURE                                                                                             \
  "AwsKWNqRHiCtdNJ0U5GXZ1H5obptEWVR1+A1kPhot4cdLfmulvBVXRaBIrP+jd2TSP2J/KNAgv2BDLH7DXUibdTnzJaKm/"                     \
  "QKAjpwpuShnV6Y9KSWTnomBw9x9OWDkVrBzSo5rOFpHHOTZJhp4ygStKEzZDa108g8uP5PpkfzntO2eIVEOdMHoL9/"                         \
  "yAkuYJcz+VmCH+1AJtCdeKfhjfmlk0bP72fwsait6pA3TW0iEll9ptZmlLjNtCTi982h1yNprh+XtrjMz7ClbJChQf3LLHiJMZ+"                \
  "7r4yKTrehdBVfxQoNNw9r2D7TBRaY8bXYwMombMHRuu0oVbqNU1jEs60NGQ=="

int main() {
  int ret = 1;

  const char *privatekeybase64 = PRIVATE_KEY_BASE64;
  const size_t privatekeybase64len = strlen(privatekeybase64);

  atchops_rsakey_privatekey privatekey;
  atchops_rsakey_privatekey_init(&privatekey);
  ret = atchops_rsakey_populate_privatekey(&privatekey, privatekeybase64, privatekeybase64len);
  if (ret != 0) {
    printf("atchops_rsakey_populate_privatekey (failed): %d\n", ret);
    goto exit;
  }
  printf("atchops_rsakey_populate_privatekey (success): %d\n", ret);

  unsigned char *signature = malloc(sizeof(unsigned char) * SIGNATURE_BUFFER_LEN);
  memset(signature, 0, SIGNATURE_BUFFER_LEN);
  size_t signatureolen = 0;

  const char *message = MESSAGE;
  const size_t messagelen = strlen(message);

  ret = atchops_rsa_sign(privatekey, MBEDTLS_MD_SHA256, (const unsigned char *)message, messagelen, signature,
                         SIGNATURE_BUFFER_LEN, &signatureolen);
  if (ret != 0) {
    printf("atchops_rsa_sign (failed): %d\n", ret);
    goto exit;
  }
  printf("atchops_rsa_sign (success): %d\n", ret);
  printf("signature: \"%s\"\n", signature);

  ret = memcmp(signature, (const unsigned char *)EXPECTED_SIGNATURE, signatureolen);
  if (ret != 0) {
    printf("memcmp (failed): %d\n", ret);
    printf("got: \"%s\" | expected: \"%s\"\n", signature, EXPECTED_SIGNATURE);
    goto exit;
  }

  printf("memcmp (success): %d\n", ret);

  goto exit;

exit: {
  free(signature);
  return ret;
}
}
