#pragma once

#include "at_chops_type.h"

namespace AtChopsKey
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

  typedef struct AsymmetricKeyPair
  {
    size_t publicKeyLen;
    DartType::String publicKey;
    size_t privateKeyLen;
    DartType::String privateKey;
  } AsymmetricKeyPair;

  typedef struct SymmetricKey
  {
    size_t keyLen;
    DartType::String key;
  } SymmetricKey;

  AsymmetricKeyPair createAsymmetricKeyPair(DartType::String publicKey, DartType::String privateKey)
  {
    return (AsymmetricKeyPair){
        sizeof(publicKey),
        publicKey,
        sizeof(privateKey),
        privateKey,
    };
  };

  SymmetricKey createSymmetricKey(DartType::String key)
  {
    return (SymmetricKey){sizeof(key), key};
  };
}
