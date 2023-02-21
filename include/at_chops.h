#pragma once

#include "at_chops_algorithm.h"
#include "at_chops_key.h"
#include "at_chops_type.h"
#include "at_chops_metadata.h"

namespace AtChops
{
  // AtChops
  AtChopsMetaData::AtEncryptionResult decryptBytes(DartType::Uint8List data, size_t dataLen, AtChopsKey::EncryptionKeyType encryptionKeyType);
  AtChopsMetaData::AtEncryptionResult decryptString();

  AtChopsMetaData::AtEncryptionResult encryptBytes();
  AtChopsMetaData::AtEncryptionResult encryptString();

  DartType::String hash();

  AtChopsMetaData::AtSigningResult signBytes();
  AtChopsMetaData::AtSigningResult signString();

  AtChopsMetaData::AtSigningResult verifySignatureBytes();
  AtChopsMetaData::AtSigningResult verifySignatureString();

}
