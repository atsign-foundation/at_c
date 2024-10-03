#include <atchops/base64.h>
#include <atchops/constants.h>
#include <atchops/rsa_key.h>
#include <atlogger/atlogger.h>
#include <mbedtls/asn1.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define TAG "main"

#define BAD_KEY_PEM_FORMAT                                                                                             \
  "-----BEGIN RSA PRIVATE KEY-----\n"                                                                                  \
  "MIIEowIBAAKCAQEAs5+9gtnzTsz91MMt4JEkImD0GpczCCZ8jOdWpo2M7Gj9tAjaOctjUFejcdW8HKZ9TAaD8eACtuoQ+ \n"                   \
  "3fYo4zktpVOYJT4kn9GQOvHtuM4uzbMkYLw9Y4WB9h/"                                                                        \
  "HKDXO3kZbpH8v+wWybH9h99wgXIyz1xHaeOpHQAaj+ornW18xt9x0Chp342mkFlh3j3TVN09W7U0CfDL/rB/ \n"                            \
  "nGieg3UbveWXSrqIlYqe6hwmdo5TR5+OgSY0i/a9jImBdouBv6ZHZklbwtecZ6f8dd3/hgyiDAHq4+tiNFMhmrEyUJXxJ9cGATZYISpSMsjErBab/ " \
  "\n"                                                                                                                 \
  "VIIv0dOoCtxhk2ni+5GZjUPCQIDAQABAoIBABEglShp8co8v6NO7QvxqvlgN0ZlzmbjjJK+6EM/UgWkyTQmd/ \n"                           \
  "B01UZu5NXQ5Hvy4BWktWYVzwxz6ySfO9f0ckZ6nBuXeNA3NJKyKLvmlJ09T2o8iw9O+ \n"                                             \
  "gjLeutW5s7z8Bnb77a5Iz8eKqePBaJCKlgdW23cWF68iMvaL0h2jSRFNyGKblANAVt+/ \n"                                            \
  "fK7IcECtVJaytAXUrX1z6Zje7AnW8pm+GrScpxaqGaYdAaGwuIV4F2sUnjYWOaSBn7kHfe3rRavb97BXJ+mY8Ayc0aK5n3+ \n"                 \
  "BO020R0PWJdm9LW9ZM9nKVBagK+2qd9kXui2fEw99hlU0WFa4hQJ+ \n"                                                           \
  "r9jpsLl1OUCgYEA3YC4gRBNO0VKsCzzUfAppyIicaKcTJXe5SRVnMDThOH8bDmcy589l8JdtX/ \n"                                      \
  "18qN90cQDDblvT76iKE31UU9AH5wyDaeBlOxpbxXbVlkO5CSwAKpJcxMlP+e4PbN5t+ \n"                                             \
  "H6cyDjk8QAbnFBoH6J35thHSdOxXRFKBiFGjbzjQFSYYsCgYEAz5lRWrfDyDnL0YjvijIBx0JgXRkejYgDjr6SfdzjjDeviSJzVysYhNSL/ \n"     \
  "GoMNtIQrTsfS3sIKAAsNdlKkhwvuASR2rI01K6yopJZnQzIxUgvV62ej7k6boLv8DOoeH4cH9yvTxFcdZg5QGaEn8IUODBpKim3sKrxsPUu6M+ \n"  \
  "UPDsCgYEApnBbs3dpYRkfFySfrTk2Q0UN9q9GnPGcrDfSMNhf2CDrSPM9k2/Tm15Mhd5iE/Gv0FhmJwDo2FYZiQmTRYa0W0xF/ \n"              \
  "Caa4ymFzBfzWX3QB7RdoBJU4KhJPCzFL2/ \n"                                                                              \
  "WDUs7oxjaiKUl4dcuhgevWBtsLLjlos9MS+ \n"                                                                             \
  "Wo1lrmRVTx7yMCgYA627hCJTngCerspIttvhHdAce6fYW5EOgZT5TPFJJ7Tcp58geLnk9cUbrCvPprjJFn3AxaZS6B0NK4DbxjwpQQ81K7E62A42sI" \
  "\n"                                                                                                                 \
  "RsAbk+VUccviavo6u4SCkqMekjbguriUnAgkPcLeIGOTC73sYaVD7Q3UA3HuJ/ \n"                                                  \
  "lQd6NuJHRdwwKBgHOKt9BbHsUymTTFHpJA5t2WHRgmKEQxefgNiTkk6pUirm29XX0sRj7wXueXUnztRtMke2fK2XBtPuoHb+ \n"                \
  "raovp3UVclQKRrnrTCu44Yrss2BL/XSVnb1QYOU+/hJWilMcwBGqRGi71aZYPFwY6t3NQcBRY9PE/ui13d4MtXrvdo\n"                       \
  "-----END RSA PRIVATE KEY-----"

#define BAD_KEY                                                                                                        \
  "MIIEowIBAAKCAQEAs5+9gtnzTsz91MMt4JEkImD0GpczCCZ8jOdWpo2M7Gj9tAjaOctjUFejcdW8HKZ9TAaD8eACtuoQ+"                      \
  "3fYo4zktpVOYJT4kn9GQOvHtuM4uzbMkYLw9Y4WB9h/"                                                                        \
  "HKDXO3kZbpH8v+wWybH9h99wgXIyz1xHaeOpHQAaj+ornW18xt9x0Chp342mkFlh3j3TVN09W7U0CfDL/rB/"                               \
  "nGieg3UbveWXSrqIlYqe6hwmdo5TR5+OgSY0i/a9jImBdouBv6ZHZklbwtecZ6f8dd3/hgyiDAHq4+tiNFMhmrEyUJXxJ9cGATZYISpSMsjErBab/"  \
  "VIIv0dOoCtxhk2ni+5GZjUPCQIDAQABAoIBABEglShp8co8v6NO7QvxqvlgN0ZlzmbjjJK+6EM/UgWkyTQmd/"                              \
  "B01UZu5NXQ5Hvy4BWktWYVzwxz6ySfO9f0ckZ6nBuXeNA3NJKyKLvmlJ09T2o8iw9O+"                                                \
  "gjLeutW5s7z8Bnb77a5Iz8eKqePBaJCKlgdW23cWF68iMvaL0h2jSRFNyGKblANAVt+/"                                               \
  "fK7IcECtVJaytAXUrX1z6Zje7AnW8pm+GrScpxaqGaYdAaGwuIV4F2sUnjYWOaSBn7kHfe3rRavb97BXJ+mY8Ayc0aK5n3+"                    \
  "BO020R0PWJdm9LW9ZM9nKVBagK+2qd9kXui2fEw99hlU0WFa4hQJ+"                                                              \
  "r9jpsLl1OUCgYEA3YC4gRBNO0VKsCzzUfAppyIicaKcTJXe5SRVnMDThOH8bDmcy589l8JdtX/"                                         \
  "18qN90cQDDblvT76iKE31UU9AH5wyDaeBlOxpbxXbVlkO5CSwAKpJcxMlP+e4PbN5t+"                                                \
  "H6cyDjk8QAbnFBoH6J35thHSdOxXRFKBiFGjbzjQFSYYsCgYEAz5lRWrfDyDnL0YjvijIBx0JgXRkejYgDjr6SfdzjjDeviSJzVysYhNSL/"        \
  "GoMNtIQrTsfS3sIKAAsNdlKkhwvuASR2rI01K6yopJZnQzIxUgvV62ej7k6boLv8DOoeH4cH9yvTxFcdZg5QGaEn8IUODBpKim3sKrxsPUu6M+"     \
  "UPDsCgYEApnBbs3dpYRkfFySfrTk2Q0UN9q9GnPGcrDfSMNhf2CDrSPM9k2/Tm15Mhd5iE/Gv0FhmJwDo2FYZiQmTRYa0W0xF/"                 \
  "Caa4ymFzBfzWX3QB7RdoBJU4KhJPCzFL2/"                                                                                 \
  "WDUs7oxjaiKUl4dcuhgevWBtsLLjlos9MS+"                                                                                \
  "Wo1lrmRVTx7yMCgYA627hCJTngCerspIttvhHdAce6fYW5EOgZT5TPFJJ7Tcp58geLnk9cUbrCvPprjJFn3AxaZS6B0NK4DbxjwpQQ81K7E62A42sI" \
  "RsAbk+VUccviavo6u4SCkqMekjbguriUnAgkPcLeIGOTC73sYaVD7Q3UA3HuJ/"                                                     \
  "lQd6NuJHRdwwKBgHOKt9BbHsUymTTFHpJA5t2WHRgmKEQxefgNiTkk6pUirm29XX0sRj7wXueXUnztRtMke2fK2XBtPuoHb+"                   \
  "raovp3UVclQKRrnrTCu44Yrss2BL/XSVnb1QYOU+/hJWilMcwBGqRGi71aZYPFwY6t3NQcBRY9PE/ui13d4MtXrvdo"

int main() {

  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  /*
   * 2. Variables
   */
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  unsigned char buf[8192];
  memset(buf, 0, sizeof(buf));

  //   mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
  //   if ((ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)BAD_KEY_PEM_FORMAT, strlen(BAD_KEY_PEM_FORMAT) + 1,
  //   NULL,
  //                                   0, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
  //     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "mbedtls_pk_parse_key failed: %d\n", ret);
  //     goto exit;
  //   }

  size_t olen = 0;
  if ((ret = atchops_base64_decode(BAD_KEY, strlen(BAD_KEY), buf, sizeof(buf), &olen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode failed: %d\n", ret);
    goto exit;
  }

  for (size_t i = 0; i < olen; i++) {
    atlogger_log(NULL, ATLOGGER_LOGGING_LEVEL_DEBUG, "%02x ", buf[i]);
  }
  atlogger_log(NULL, ATLOGGER_LOGGING_LEVEL_DEBUG, "\n");

  unsigned char total[8192];
  memset(total, 0, sizeof(total));

  // PrivateKeyInfo SEQUENCE (3 elements)
  total[0] = 0x30; // constructed sequence tag
  total[1] = 0x82; // 8 --> 1000 0000 (1 in MSB means that it is long form) and 2 --> 0010 0000 (the next 2 bytes are the length of data)
  size_t total_len = 22 + olen;
  total[2] = (unsigned char)((total_len >> 8) & 0xFF);
  total[3] = (unsigned char)(total_len & 0xFF);

  // version INTEGER 0
  total[4] = 0x02; // integer tag
  total[5] = 0x01; // length of data
  total[6] = 0x00; // data

  // private key algorithm identifier
  total[7] = 0x30; // constructed sequence tag
  total[8] = 0x0D; // there are 2 elements in the sequence
  total[9] = 0x06;
  total[10] = 0x09;
  total[11] = 0x2A;
  total[12] = 0x86;
  total[13] = 0x48;
  total[14] = 0x86;
  total[15] = 0xF7;
  total[16] = 0x0D;
  total[17] = 0x01;
  total[18] = 0x01;
  total[19] = 0x01;
  total[20] = 0x05;
  total[21] = 0x00;

  // PrivateKey OCTET STRING (length of `olen`)
  total[22] = 0x04; // octet string tag
  total[23] = 0x82; // 8 --> 1000 0000 (1 in MSB means that it is long form) and 2 --> 0010 0000 (the next 2 bytes are the length of data)
  total[24] = (unsigned char)((olen >> 8) & 0xFF); // length of data
  total[25] = (unsigned char)(olen & 0xFF); // length of data

  memcpy(total + 26, buf, olen);

  // base64 encode buf into buf1
  unsigned char buf1[8192];
  memset(buf1, 0, sizeof(buf1));

  size_t olen1 = 0;
  if ((ret = atchops_base64_encode(total, 26 + olen, buf1, sizeof(buf1), &olen1)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode failed: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "olen1: %d\n", olen1);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "buf1: %s\n", buf1);

exit: {
  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  return ret;
}
}
