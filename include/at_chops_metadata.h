#pragma once

#include "at_chops_type.h"
#include "at_chops_key.h"

namespace AtChopsMetaData
{
  // Encryption

  typedef enum AtEncryptionResultType
  {
    bytes,
    string
  } AtEncryptionResultType;

  typedef union AtEncryptionResultUnion
  {
    DartType::Uint8List bytes;
    DartType::String string;
  } AtEncryptionResultUnion;

  typedef struct AtEncryptionMetaData
  {
    DartType::String atEncryptionAlgorithm;
    DartType::String keyName;
    AtChopsKey::EncryptionKeyType encryptionKeyType;
    AtChopsType::InitialisationVector iv;
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
    DartType::Uint8List bytes;
    DartType::String string;
    DartType::Boolean boolean;
  } AtSigningResultUnion;

  typedef struct AtSigningMetaData
  {
    DartType::String atSigningAlgorithm;
    AtChopsKey::SigningKeyType signingKeyType;
  } AtSigningMetaData;

  typedef struct AtSigningResult
  {
    AtSigningResultType atSigningResultType;
    AtSigningResultUnion result;
    AtSigningMetaData atSigningMetaData;
  } AtSigningResult;
}
