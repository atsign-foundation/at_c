#pragma once

#include "at_chops_type.h"

typedef struct AsymmetricKeyPair
{
  size_t publicKeyLen;
  char *publicKey;
  size_t privateKeyLen;
  char *privateKey;
} AsymmetricKeyPair;

typedef AsymmetricKeyPair AtEncryptionKeyPair;
typedef AsymmetricKeyPair AtPkamKeyPair;
typedef AsymmetricKeyPair AtSigningKeyPair;

typedef struct SymmetricKey
{
  size_t keyLen;
  char *key;
} SymmetricKey;

AsymmetricKeyPair createAsymmetricKeyPair(char *publicKey, char *privateKey);
// {
//   return (AsymmetricKeyPair){
//       sizeof(publicKey),
//       publicKey,
//       sizeof(privateKey),
//       privateKey,
//   };
// };

AtEncryptionKeyPair createEncryptionKeyPair(char *publicKey, char *privateKey);
AtPkamKeyPair createPkamKeyPair(char *publicKey, char *privateKey);
AtSigningKeyPair createSigningKeyPair(char *publicKey, char *privateKey);

SymmetricKey createSymmetricKey(char *key);
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
