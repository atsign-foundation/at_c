#pragma once

#include "at_chops_type.h"
#include "at_chops_keys.h"
#include "at_chops_algorithm.h"
#include "at_chops_metadata.h"

// AtChops
AtEncryptionResult decryptBytes(uint8_t *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);
AtEncryptionResult decryptString(char *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);

AtEncryptionResult encryptBytes(uint8_t *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);
AtEncryptionResult encryptString(char *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);

char *hash(uint8_t *signedData, size_t signedDataLen, AtHashingAlgorithm atHashingAlgorithm);

AtSigningResult signBytes(uint8_t data, size_t dataLen, AtSigningMetaData atSigningMetaData);
AtSigningResult signString(char *data, size_t dataLen, AtSigningMetaData atSigningMetaData);

AtSigningResult verifySignatureBytes(uint8_t *data, size_t dataLen, AtSigningMetaData atSigningMetaData);
AtSigningResult verifySignatureString(char *data, size_t dataLen, AtSigningMetaData atSigningMetaData);
