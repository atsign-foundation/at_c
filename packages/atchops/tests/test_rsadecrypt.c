#include "atchops/rsa.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// a pkcs8 formatted key in base64 from C SDK generation
// #define PRIVATEKEYBASE64
// "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzn72C2fNOzP3Uwy3gkSQiYPQalzMIJnyM51amjYzsaP20CNo5y2NQV6Nx1bwcpn1MBoPx4AK26hD7d9ijjOS2lU5glPiSf0ZA68e24zi7NsyRgvD1jhYH2H8coNc7eRlukfy/7BbJsf2H33CBcjLPXEdp46kdABqP6iudbXzG33HQKGnfjaaQWWHePdNU3T1btTQJ8Mv+sH+caJ6DdRu95ZdKuoiVip7qHCZ2jlNHn46BJjSL9r2MiYF2i4G/pkdmSVvC15xnp/x13f+GDKIMAerj62I0UyGasTJQlfEn1wYBNlghKlIyyMSsFpv9Ugi/R06gK3GGTaeL7kZmNQ8JAgMBAAECggEAESCVKGnxyjy/o07tC/Gq+WA3RmXOZuOMkr7oQz9SBaTJNCZ38HTVRm7k1dDke/LgFaS1ZhXPDHPrJJ871/RyRnqcG5d40Dc0krIou+aUnT1PajyLD076CMt661bmzvPwGdvvtrkjPx4qp48FokIqWB1bbdxYXryIy9ovSHaNJEU3IYpuUA0BW3798rshwQK1UlrK0BdStfXPpmN7sCdbymb4atJynFqoZph0BobC4hXgXaxSeNhY5pIGfuQd97etFq9v3sFcn6ZjwDJzRormff4E7TbRHQ9Yl2b0tb1kz2cpUFqAr7ap32Re6LZ8TD32GVTRYVriFAn6v2OmwuXU5QKBgQDdgLiBEE07RUqwLPNR8CmnIiJxopxMld7lJFWcwNOE4fxsOZzLnz2Xwl21f/Xyo33RxAMNuW9PvqIoTfVRT0AfnDINp4GU7GlvFdtWWQ7kJLAAqklzEyU/57g9s3m34fpzIOOTxABucUGgfonfm2EdJ07FdEUoGIUaNvONAVJhiwKBgQDPmVFat8PIOcvRiO+KMgHHQmBdGR6NiAOOvpJ93OOMN6+JInNXKxiE1Iv8agw20hCtOx9LewgoACw12UqSHC+4BJHasjTUrrKiklmdDMjFSC9XrZ6PuTpugu/wM6h4fhwf3K9PEVx1mDlAZoSfwhQ4MGkqKbewqvGw9S7oz5Q8OwKBgQCmcFuzd2lhGR8XJJ+tOTZDRQ32r0ac8ZysN9Iw2F/YIOtI8z2Tb9ObXkyF3mIT8a/QWGYnAOjYVhmJCZNFhrRbTEX8JprjKYXMF/NZfdAHtF2gElTgqEk8LMUvb9YNSzujGNqIpSXh1y6GB69YG2wsuOWiz0xL5ajWWuZFVPHvIwKBgDrbuEIlOeAJ6uyki22+Ed0Bx7p9hbkQ6BlPlM8UkntNynnyB4ueT1xRusK8+muMkWfcDFplLoHQ0rgNvGPClBDzUrsTrYDjawhGwBuT5VRxy+Jq+jq7hIKSox6SNuC6uJScCCQ9wt4gY5MLvexhpUPtDdQDce4n+VB3o24kdF3DAoGAc4q30FsexTKZNMUekkDm3ZYdGCYoRDF5+A2JOSTqlSKubb1dfSxGPvBe55dSfO1G0yR7Z8rZcG0+6gdv6tqi+ndRVyVApGuetMK7jhiuyzYEv9dJWdvVBg5T7+ElaKUxzAEapEaLvVplg8XBjq3c1BwFFj08T+6LXd3gy1eu92g="

// a pkcs8 formatted key in base64 from Dart SDK generation
#define PRIVATEKEYBASE64                                                                                               \
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

#define CIPHERTEXTBASE64                                                                                               \
  "QVZmFo7iE0qr8QbF9pwBM9/AwPezOe+zzzSl2J/CKkyjwc8RsU4MCi5Mr/"                                                         \
  "L09S+t8j3a092pax6OglKeS49xGlfmBWoFoCStb98T+"                                                                        \
  "ifwlYFnnKiSehDqUh3tvtMDgmmiUVxbCKR5CTsQYndGVeQaKhCLzl2Pv5OOutP9Uon2C42NQK3nOlEV7vMIlzY/"                            \
  "HyiSWU+0sUkWLG01lChjI4m8cdfLjM/c+vxJe8qOFJKewtAuTdg63Q0tR0qZ/O7EHJ1JMKdc/fPFpKz8whZAevhx3UIIzilI7xBluMYKEi4jDH/"    \
  "p4UARTc1LALGE/7eQ5mVdPsdPU/h4Jd5jWbkXWOA1nA=="

int main() {
  int ret = 1;

  const char *privatekeybase64 = PRIVATEKEYBASE64;
  const size_t privatekeybase64len = strlen(privatekeybase64);

  const char *ciphertext = CIPHERTEXTBASE64;
  const size_t ciphertextlen = strlen(ciphertext);

  atchops_rsa_key_private_key privatekey;
  atchops_rsa_key_private_key_init(&privatekey);

  const size_t plaintextsize = 4096;
  unsigned char plaintext[plaintextsize];
  memset(plaintext, 0, sizeof(unsigned char) * plaintextsize);
  size_t plaintextlen = 0;

  ret = atchops_rsa_key_populate_private_key(&privatekey, privatekeybase64, privatekeybase64len);
  if (ret != 0) {
    printf("atchops_rsa_key_populate_private_key (failed): %d\n", ret);
    goto ret;
  }
  printf("atchops_rsa_key_populate_private_key (success): %d\n", ret);

  ret = atchops_rsa_decrypt(&privatekey, (const unsigned char *)ciphertext, ciphertextlen, plaintext, plaintextsize,
                            &plaintextlen);
  if (ret != 0) {
    printf("atchops_rsa_decrypt (failed): %d\n", ret);
    goto ret;
  }
  printf("atchops_rsa_decrypt (success): %d\n", ret);
  printf("plaintext: \"%s\"\n", plaintext);

  goto ret;

ret: { return ret; }
}
