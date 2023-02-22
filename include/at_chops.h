#pragma once

#include "at_chops_algorithm.h"
#include "at_chops_keys.h"
#include "at_chops_type.h"
#include "at_chops_metadata.h"

namespace AtChops
{
  // AtChops
  AtChopsMetaData::AtEncryptionResult decryptBytes(DartType::Uint8List data, size_t dataLen, AtChopsMetaData::AtEncryptionMetaData atEncryptionMetaData);
  AtChopsMetaData::AtEncryptionResult decryptString(DartType::String data, size_t dataLen, AtChopsMetaData::AtEncryptionMetaData atEncryptionMetaData);

  AtChopsMetaData::AtEncryptionResult encryptBytes(DartType::Uint8List data, size_t dataLen, AtChopsMetaData::AtEncryptionMetaData atEncryptionMetaData);
  AtChopsMetaData::AtEncryptionResult encryptString(DartType::String data, size_t dataLen, AtChopsMetaData::AtEncryptionMetaData atEncryptionMetaData);

  DartType::String hash(DartType::Uint8List signedData, size_t signedDataLen, AtChopsAlgorithm::AtHashingAlgorithm atHashingAlgorithm);

  AtChopsMetaData::AtSigningResult signBytes(DartType::Uint8List data, size_t dataLen, AtChopsMetaData::AtSigningMetaData atSigningMetaData);
  AtChopsMetaData::AtSigningResult signString(DartType::String data, size_t dataLen, AtChopsMetaData::AtSigningMetaData atSigningMetaData);

  AtChopsMetaData::AtSigningResult verifySignatureBytes(DartType::Uint8List data, size_t dataLen, AtChopsMetaData::AtSigningMetaData atSigningMetaData);
  AtChopsMetaData::AtSigningResult verifySignatureString(DartType::String data, size_t dataLen, AtChopsMetaData::AtSigningMetaData atSigningMetaData);
}
