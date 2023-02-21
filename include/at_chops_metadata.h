#pragma once

#include "at_chops_type.h"
#include "at_chops_key.h"
#include <stdbool.h>

namespace AtChopsMetaData
{
  // Encryption

  enum AtEncryptionResultType
  {
    bytes,
    string
  };

  union AtEncryptionResultUnion
  {
    DartType::Uint8List bytes;
    DartType::String string;
  };

  struct AtEncryptionMetaData
  {
    DartType::String atEncryptionAlgorithm;
    DartType::String keyName;
    AtChopsKey::EncryptionKeyType encryptionKeyType;
    AtChopsType::InitialisationVector iv;
  };

  struct AtEncryptionResult
  {
    AtEncryptionResultType atEncryptionResultType;
    AtEncryptionResultUnion result;
    AtEncryptionMetaData atEncryptionMetaData;
  };

  // Signing

  enum AtSigningResultType
  {
    bytes,
    string,
    boolean
  };

  union AtSigningResultUnion
  {
    DartType::Uint8List bytes;
    DartType::String string;
    bool boolean;
  };

  struct AtSigningMetaData
  {
    DartType::String atSigningAlgorithm;
    AtChopsKey::SigningKeyType signingKeyType;
  };

  struct AtSigningResult
  {
    AtSigningResultType atSigningResultType;
    AtSigningResultUnion result;
    AtSigningMetaData atSigningMetaData;
  };
}