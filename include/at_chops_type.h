#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint8_t
#include <stdbool.h> // bool

typedef enum EncryptionKeyType
{
  rsa2048,
  rsa4096,
  ecc,
  aes128,
  aes192,
  aes256
} EncryptionKeyType;

typedef enum SigningKeyType
{
  pkamSha256,
  signingSha256
} SigningKeyType;

typedef struct InitialisationVector
{
  size_t ivLen;
  uint8_t *iv;
} InitialisationVector;
