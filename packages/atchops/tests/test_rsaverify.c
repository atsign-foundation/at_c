#include "atchops/rsa.h"
#include <mbedtls/md.h>
#include <stdio.h>
#include <string.h>

#define PUBLIC_KEY_BASE64                                                                                              \
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuA7KmWrIPcKTH3hSzsDZ"                                                   \
  "ys60kxaqKgHeTuGCwgzHSi2SkMV9iYBCd2//KagWVoUKWyuI2KOQo2WFslqFOjOs"                                                   \
  "j4NqlhM3EamBqZqVFI5IUHtTNbXcea3igp4nVWoHwPHyJNiMf0I0rHSUeiuAbeR5"                                                   \
  "6lYGE8b64fXzKkRyQ7YRVyrp7HtYRrmA27xGDtAKT9mr+0T+5lzsHR1YLT3capll"                                                   \
  "nlUf5w8p6l8DJ4qGnODpG4/gOggEr6H5/aAVjGn8WGuRY9d7SZLJfeYG+vJ1/o/P"                                                   \
  "37L5/7sc2D6kYS1Qh45EN0jUF8ILRUJRNFKZpqWDn64LKHKCwKz00NT6OANUHNdF"                                                   \
  "awIDAQAB"

#define PRIVATE_KEY_BASE64                                                                                             \
  "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC4DsqZasg9wpMf"                                                   \
  "eFLOwNnKzrSTFqoqAd5O4YLCDMdKLZKQxX2JgEJ3b/8pqBZWhQpbK4jYo5CjZYWy"                                                   \
  "WoU6M6yPg2qWEzcRqYGpmpUUjkhQe1M1tdx5reKCnidVagfA8fIk2Ix/QjSsdJR6"                                                   \
  "K4Bt5HnqVgYTxvrh9fMqRHJDthFXKunse1hGuYDbvEYO0ApP2av7RP7mXOwdHVgt"                                                   \
  "PdxqmWWeVR/nDynqXwMnioac4Okbj+A6CASvofn9oBWMafxYa5Fj13tJksl95gb6"                                                   \
  "8nX+j8/fsvn/uxzYPqRhLVCHjkQ3SNQXwgtFQlE0UpmmpYOfrgsocoLArPTQ1Po4"                                                   \
  "A1Qc10VrAgMBAAECggEBAJ+FMlKFGcdtO9WqkxpeSmRbgmV430JJHEOBb7J/ILpJ"                                                   \
  "hR20DHl/kBu0FZIk/DdAVxltQc2A9XqoIpfRnGY1Ivm/DEHFpZTJNHeqYkrOhh46"                                                   \
  "xINoew16hzZtm+mLW+z9xL/qbtpcpwpQf97ilQypWICgzeOWMRpl77pSWDYXNjA0"                                                   \
  "qQP/Y6A2ocAYBVkBz/SGtpWBRKb/CouzvDUqiDAa0EEKTu/Ywa9yz2GGd+eUxk2F"                                                   \
  "sM20zTmZfUipaIWkrS0bOevAcUvcVaX9Ydq1vKXa34+oZcNQqW/sS4+B+RM3ogl8"                                                   \
  "Lg2PCLYQG7azSSFHCJPwG5u7RyMWjLXwPrVkT1Nj3wECgYEA2guA5gMp7LAtmH1k"                                                   \
  "PFOz2kENveBYW1o/xzgvaBlLCZUubQCE55zlbyAMQUtEuzkyz8dT6SDLkllsDASt"                                                   \
  "30et9g8rDqa2//gK3O/mfSsx64pOqRXgr0Fb1OmHP0ESGoj3xt4pS8wENtUiwfeA"                                                   \
  "U2j+NPU4t9Y1iqslVsBJVIImLpcCgYEA2BjBcWZ9QNmFbE0rlX3+G3GQH4amc5RJ"                                                   \
  "2AUt6EyIexAZNr+1cpTGKswePw3EWwQz0sbC/Fci4qfsR5+d4rfcJp75mSV3HHEl"                                                   \
  "Z6m7iH50zKIVePSRrlgMzOPmpEoo2VelLFVx/sP70s4sPNZyKQZngn78MgtcOqQK"                                                   \
  "jTtIU96JDk0CgYEAiLLTkeCD5Tair0pVkBit1fQY6GSBIGyZNY288teAmrZjT8UW"                                                   \
  "jZpooN2HsVu98F6ww2Dk83AzEEJtoa9BTo1Cu9PQm7PbYOih7tecOfbdqhygqhLk"                                                   \
  "NRuVtgreVsK11dru9EeNvk5eif3fd5lyY1icnpjqgR6TnKcllpigoJGj3GsCgYA0"                                                   \
  "mHnkruxHb2oA/RthjEPfzBknAy/aK7p5YHFW++GwCjAI2kpAdCNzYTDvadtjx7cR"                                                   \
  "Ux08K70q63If0KKt/tAPelwHwU2nV4aiH3asdxLYh46wXN5kT7v11nZZgE9G7wUd"                                                   \
  "sEJJnsvY+CNeP1eT0qI46c1aJNey0iBbVZV6DEzRdQKBgQCPtEKSHGDom9bTErpL"                                                   \
  "TJ//6ZIrUlS+5mpCIOTgA1lyTORq9Xe+qMD7FbFQNDdlNuXtBKvwu5vYJ6Ib+VIt"                                                   \
  "sDFCwDRQsGFXNkdnSFZovMfmNQp+p6fuOgrnuSfLR1gI8nV3JQy8U/eZT5ABh06j"                                                   \
  "3A6sUy0M7TXTd6ljRS3MRBatOA=="

#define SIGNATURE_SIZE 256
#define SIGNATURE_BASE64_SIZE 2048

#define MESSAGE "_4a160d33-0c63-4800-bee0-ee254752f8c8@jeremy_0:6c987cc1-0dde-4ba1-af56-a9677086182"

#define EXPECTED_SIGNATURE                                                                                             \
  "OHgiJttksA/47D6fvjwb5LhR8AqxFzegf/QfkFvPZgnCM1OtMY7qML7NuuO4hQI0685Yap"                                             \
  "xzMDqYNOwpFylKRJJ83V7GHrcBbAs37/UykDvqw6U9L5lo1BXrwJfcBMUejMcgnmTYOP+z"                                             \
  "/VRzrCAwCYtfWBAwOM0huYQB0nwIc/UOUX1qNbjGeZVwe09WjjpgOxRdSLgC2rF4E9hAt"                                              \
  "hnIppWX5yXScbbZgcaTZjp57z5H959nc424ScItxOqM1+hVX64pXHHKHjOFQknHsgw9e6"                                              \
  "qh7LeuVvActKJwlFF0yUbiSX4v1Urm50Lk9IqMEqLrbo49BW2eYblEjMsMBlcJag=="

int main() {

  int ret = 1;

  atchops_rsa_key_public_key publickey;
  atchops_rsa_key_public_key_init(&publickey);

  atchops_rsa_key_private_key privatekey;
  atchops_rsa_key_private_key_init(&privatekey);

  const char *message = MESSAGE;
  const size_t messagelen = strlen(message);

  unsigned char signature[SIGNATURE_SIZE];
  memset(signature, 0, sizeof(unsigned char) * SIGNATURE_SIZE);

  unsigned char verifiedsignature[SIGNATURE_SIZE];
  memset(verifiedsignature, 0, sizeof(unsigned char) * SIGNATURE_SIZE);

  char signaturebase64[SIGNATURE_BASE64_SIZE];
  memset(signaturebase64, 0, sizeof(char) * SIGNATURE_BASE64_SIZE);
  size_t signaturebase64len = 0;

  ret = atchops_rsa_key_populate_private_key(&privatekey, PRIVATE_KEY_BASE64, strlen(PRIVATE_KEY_BASE64));
  if (ret != 0) {
    printf("atchops_rsa_key_populate_private_key (failed): %d\n", ret);
    goto exit;
  }

  ret = atchops_rsa_sign(&privatekey, ATCHOPS_MD_SHA256, (const unsigned char *)message, messagelen, signature);
  if (ret != 0) {
    printf("atchops_rsa_sign (failed): %d\n", ret);
    goto exit;
  }

  ret = atchops_rsa_key_populate_public_key(&publickey, PUBLIC_KEY_BASE64, strlen(PUBLIC_KEY_BASE64));
  if (ret != 0) {
    printf("atchops_rsa_key_populate_public_key (failed): %d\n", ret);
    goto exit;
  }

  ret = atchops_rsa_verify(&publickey, ATCHOPS_MD_SHA256, (const unsigned char *)message, messagelen, signature);
  if (ret != 0) {
    printf("atchops_rsa_verify (failed): %d\n", ret);
    goto exit;
  }

  printf("atchops_rsa_verify (success): %d\n", ret);

  goto exit;

exit: { return ret; }
}
