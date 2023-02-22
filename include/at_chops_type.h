#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint8_t
#include <stdbool.h> // bool

typedef struct
{
  size_t vecLen;
  uint8_t vec[];
} InitialisationVector;

typedef enum
{
  rsa2048,
  rsa4096,
  ecc,
  aes128,
  aes192,
  aes256
} EncryptionKeyType;

typedef struct
{
  EncryptionKeyType keyType;
  size_t keyLen;
  char key[];
} AtEncryptionKey;
