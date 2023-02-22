#pragma once

#include "at_chops_type.h"

namespace AtChopsKeys
{
  typedef struct AsymmetricKeyPair
  {
    size_t publicKeyLen;
    DartType::String publicKey;
    size_t privateKeyLen;
    DartType::String privateKey;
  } AsymmetricKeyPair;

  typedef AsymmetricKeyPair AtEncryptionKeyPair;
  typedef AsymmetricKeyPair AtPkamKeyPair;
  typedef AsymmetricKeyPair AtSigningKeyPair;

  typedef struct SymmetricKey
  {
    size_t keyLen;
    DartType::String key;
  } SymmetricKey;

  AsymmetricKeyPair createAsymmetricKeyPair(DartType::String publicKey, DartType::String privateKey);
  // {
  //   return (AsymmetricKeyPair){
  //       sizeof(publicKey),
  //       publicKey,
  //       sizeof(privateKey),
  //       privateKey,
  //   };
  // };

  AtEncryptionKeyPair createEncryptionKeyPair(DartType::String publicKey, DartType::String privateKey);
  AtPkamKeyPair createPkamKeyPair(DartType::String publicKey, DartType::String privateKey);
  AtSigningKeyPair createSigningKeyPair(DartType::String publicKey, DartType::String privateKey);

  SymmetricKey createSymmetricKey(DartType::String key);
  // {
  //   return (SymmetricKey){sizeof(key), key};
  // };

  typedef struct AtChopsKeys
  {
    AtEncryptionKeyPair atEncryptionKeyPair;
    AtPkamKeyPair atPkamKeyPair;
    AtSigningKeyPair atSigningKeyPair;
    SymmetricKey symmetricKey;
  } AtChopsKeys;
}
