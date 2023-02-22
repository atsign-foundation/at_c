#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint8_t
#include <stdbool.h> // bool

namespace DartType
{
  typedef uint8_t *Uint8List;
  typedef const uint8_t *ConstUint8List;

  typedef char *String;
  typedef const char *ConstString;

  typedef bool Boolean;
  typedef const bool ConstBoolean;
}

namespace AtChopsType
{
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
    DartType::Uint8List iv;
  } InitialisationVector;
}
