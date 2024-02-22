#include "atchops/rsa.h"
#include <mbedtls/md.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PRIVATE_KEY_BASE64                                                                                             \
  "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCDc/"                                                             \
  "uZ5+pmDYY1A+IQdiKeZNhRxttbYCv1aLksIP+5Fk1GJAnKlsBBum+"                                                              \
  "Tp8CjXCHk22nWSM8YesiKRQFVEQi1OS6Whs449U1oLkVSDzqRAnZaT5nI9oIh+u2jsa/"                                               \
  "7KfYOIqqN1h17GOZopsw73RZJnvISYLaarxtFABIPQ+"                                                                        \
  "gbdFfWySEaRXUW89sfg4QO7MzEd8ZwK8KLf4E9xuCMshP90p7bMAdLn98T04rVvP78W60lMXwzospBjwT6HZxCNMSfdFEmVwynivCr/"            \
  "QY2abeY1jkSFRxqYqJJYgsb1rydjN4hRp9eYRIJmT4nXJW71ByZc/wOiS/7gou/vr9jVGypAgMBAAECggEAFTkjlQypfoKOeX6///"              \
  "Ji0nnrpwBZKB6V2lBnHSXSw7pDDaEB57CBJ9uG6ir6YiWc30tBgjRNI2GngRN1DJvscP3jdLAdGXsZXUmjLYWB6imgnCIf7R9HkV7nATfN9tomfM/"  \
  "CA5ZfOiGiCaFsdfnTAF3mLWtp7/"                                                                                        \
  "13hKNnRwmqrsvUzJrqzNFqZty7YRtkm2pxxetsycq2WGKkOjwEyJdDZSI5XbQyAzuu878WEi+Th4EI2MV21jAuP7WEAZC/"                     \
  "tBSLLFSZgiHnMaMnQ9ogWnxCbdIJfWPBiK54kcDRN2o/I7iXAVD5W3oadEYgEn6SBuG4ZQtqTM8cFSofxrGuVfyQgQKBgQDZnwC501pza1Jm4/H/"   \
  "lvB67kup9EFwQFbCTjJKuHd1NuV1O0LcHER5wfgLOac2My7kXva8gsheLHdi9ciPNtqhHrJVpl4QyXYd6h7m3FImGCfd1xwqrfWPPA0aMM8e8QZGAN" \
  "rX7Z20xzEzSgMu/"                                                                                                    \
  "0trg7WS4P7ChO2VHXviEn4mMQKBgQCaorqBjvajf9wkwh5V06HmpaI8Ji7JvRD44l1G0eGJgCrSYbvFUQr4KzfaQltfwaMJnqoNVrqey9yhPaFacjI" \
  "2QbBM3zECjmasy9m20VS70QsV7XKq7tKco8M+YfUwzOFOKrpxUm/"                                                               \
  "AG7SoTmTIwsg+VkZNTPWQB74kwKmRkkj3+QKBgGxnXi8y702rWmLSjYvqHmS+K4a/"                                                  \
  "m5FVG2KzHS5HcYo8DFU3bfjDRAD69Jpy366KFIPCIlqJM1JmCBqNoJhmlMXJysALnbPzBxmjtDz/5xP+2G0TaH6CJV5yZXx0b9hT6/"             \
  "IXHuyM+xBAYWvRJIDWvzURaPN/jKhNGyQ6ial12M0hAoGAdFadbr+6O0QEwfrxi6zPD5HpvssTRF/"                                      \
  "kFvtnJdLdle9BSEqTVF4mnJMXUDPAPwiVurUORz7K5JGHih+t9zgXIs7E7vC0FLJB+"                                                 \
  "RrczzgqQauCZZrhPEy1U3e5eoOETpS1pXNsFbnprWSqxD1GgexZbtzFw350+Ul5+"                                                   \
  "nigmo6uKzECgYBuZVdUFt0XpIWZ8hugSMhCxHhNZMrOAIbQp0eXMs3U25zd8RpUx4qXK39Sp+X6Ifs8jCfSjThhI5Ip0L0/"                    \
  "vz5IyBrTUwbaCJVmLZU69UHNm2g8I6FoMQx3w7/ILo2mlfhd9QwTEzyT9dsdXq23HJeMkWzoVLieTHySu20n+PxXbQ=="

#define SIGNATURE_BUFFER_LEN 5000

#define MESSAGE "_4a160d33-0c63-4800-bee0-ee254752f8c8@jeremy_0:6c987cc1-0dde-4ba1-af56-a9677086182"

#define PUBLIC_KEY_BASE64                                                                                              \
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg3P7mefqZg2GNQPiEHYinmTYUcbbW2Ar9Wi5LCD/"                               \
  "uRZNRiQJypbAQbpvk6fAo1wh5Ntp1kjPGHrIikUBVREItTkulobOOPVNaC5FUg86kQJ2Wk+ZyPaCIfrto7Gv+"                              \
  "yn2DiKqjdYdexjmaKbMO90WSZ7yEmC2mq8bRQASD0PoG3RX1skhGkV1FvPbH4OEDuzMxHfGcCvCi3+BPcbgjLIT/dKe2zAHS5/fE9OK1bz+/"       \
  "FutJTF8M6LKQY8E+h2cQjTEn3RRJlcMp4rwq/0GNmm3mNY5EhUcamKiSWILG9a8nYzeIUafXmESCZk+J1yVu9QcmXP8Dokv+4KLv76/"            \
  "Y1RsqQIDAQAB"

int main() {
  int ret = 1;

  const char *privatekeybase64 = PRIVATE_KEY_BASE64;
  const unsigned long privatekeybase64len = strlen(privatekeybase64);

  atchops_rsakey_privatekey privatekey;
  atchops_rsakey_privatekey_init(&privatekey);
  ret = atchops_rsakey_populate_privatekey(&privatekey, privatekeybase64, privatekeybase64len);
  if (ret != 0) {
    printf("atchops_rsakey_populate_privatekey (failed): %d\n", ret);
    goto exit;
  }

  unsigned char *signature = malloc(sizeof(unsigned char) * SIGNATURE_BUFFER_LEN);
  memset(signature, 0, SIGNATURE_BUFFER_LEN);
  unsigned long signatureolen = 0;

  const char *message = MESSAGE;
  const unsigned long messagelen = strlen(message);

  ret = atchops_rsa_sign(privatekey, MBEDTLS_MD_SHA256, (const unsigned char *)message, messagelen, signature,
                         SIGNATURE_BUFFER_LEN, &signatureolen);
  if (ret != 0) {
    printf("atchops_rsa_sign (failed): %d\n", ret);
    goto exit;
  }
  atchops_rsakey_publickey publickey;
  atchops_rsakey_publickey_init(&publickey);

  ret = atchops_rsakey_populate_publickey(&publickey, PUBLIC_KEY_BASE64, strlen(PUBLIC_KEY_BASE64));
  if (ret != 0) {
    printf("atchops_rsakey_populate_publickey (failed): %d\n", ret);
    goto exit;
  }
  ret = atchops_rsa_verify(publickey, MBEDTLS_MD_SHA256, message, messagelen, signature, signatureolen);
  if (ret != 0) {
    printf("atchops_rsakey_verify (failed): %d\n", ret);
    goto exit;
  }

  printf("atchops_rsa_verify (success): %d\n", ret);
  goto exit;

exit: {
  free(signature);
  return ret;
}
}
