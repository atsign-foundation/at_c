#pragma once

#include <stddef.h>
#include "dart_type.h"

namespace AtChopsType
{
  struct InitialisationVector
  {
    size_t iv_len;
    DartType::Uint8List iv;
  };

  // struct AtEncryptionMetadata
  // {
  //   size_t atEncryptionAlgorithmLen;
  //   DartType::String atEncryptionAlgorithm;

  //   size_t keyNameLen;
  //   DartType::String keyName;

  //   EncryptionKeyType encryptionKeyType;
  //   InitialisationVector iv;
  // };

  // struct AtEncrytionResult
  // {
  //   size_t messageLen;
  //   DartType::String message;

  //   AtEncryptionResultType type;
  // };

  // struct AtSigningResult
  // {
  //   size_t message_len;
  //   DartType::String message;
  // };
}
