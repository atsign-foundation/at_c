#pragma once

#include "at_chops_type.h"
#include "at_chops_keys.h"
#include "at_chops_algorithm.h"

// Encryption

typedef enum AtEncryptionResultType
{
  bytes,
  string
} AtEncryptionResultType;

typedef union AtEncryptionResultUnion
{
  uint8_t *bytes;
  char *string;
} AtEncryptionResultUnion;

typedef struct AtEncryptionMetaData
{
  EncryptionAlgorithm encryptionAlgorithm;
  size_t keyNameLen;
  char *keyName;
  EncryptionKeyType encryptionKeyType;
  InitialisationVector iv;
} AtEncryptionMetaData;

typedef struct AtEncryptionResult
{
  AtEncryptionResultType atEncryptionResultType;
  AtEncryptionResultUnion result;
  AtEncryptionMetaData atEncryptionMetaData;
} AtEncryptionResult;

// Signing

typedef enum AtSigningResultType
{
  bytes,
  string,
  boolean
} AtSigningResultType;

typedef union AtSigningResultUnion
{
  uint8_t *bytes;
  char *string;
  bool boolean;
} AtSigningResultUnion;

typedef struct AtSigningMetaData
{
  char *atSigningAlgorithm;
  SigningKeyType signingKeyType;
} AtSigningMetaData;

typedef struct AtSigningResult
{
  AtSigningResultType atSigningResultType;
  AtSigningResultUnion result;
  AtSigningMetaData atSigningMetaData;
} AtSigningResult;
