#pragma once

#include "at_chops_type.h"

namespace AtChopsKey
{
  enum EncryptionKeyType
  {
    rsa2048,
    rsa4096,
    ecc,
    aes128,
    aes192,
    aes256
  };

  enum SigningKeyType
  {
    pkamSha256,
    signingSha256
  };

  struct AsymmetricKeyPair
  {
    DartType::String atPublicKey;
    DartType::String atPrivateKey;
  };

  AsymmetricKeyPair createAsymmetricKeyPair(DartType::String publicKey, DartType::String privateKey)
  {
    return (AsymmetricKeyPair){publicKey, privateKey};
  };

  struct SymmetricKey
  {
    DartType::String key;
  };

  SymmetricKey createSymmetricKey(DartType::String key)
  {
    return (SymmetricKey){key};
  };
}
