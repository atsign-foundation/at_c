#pragma once

#include "at_chops_type.h"
#include "at_chops_keys.h"
#include "at_chops_algorithm.h"
#include "at_chops_metadata.h"

// AtChops

extern AtEncryptionResult AtChops_decryptBytes(uint8_t *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);
extern AtEncryptionResult AtChops_decryptString(char *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);

extern AtEncryptionResult AtChops_encryptBytes(uint8_t *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);
extern AtEncryptionResult AtChops_encryptString(char *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);

extern char *AtChops_hash(uint8_t *signedData, size_t signedDataLen, AtHashingAlgorithm atHashingAlgorithm);

extern AtSigningResult AtChops_signBytes(uint8_t data, size_t dataLen, AtSigningMetaData atSigningMetaData);
extern AtSigningResult AtChops_signString(char *data, size_t dataLen, AtSigningMetaData atSigningMetaData);

extern AtSigningResult AtChops_verifySignatureBytes(uint8_t *data, size_t dataLen, AtSigningMetaData atSigningMetaData);
extern AtSigningResult AtChops_verifySignatureString(char *data, size_t dataLen, AtSigningMetaData atSigningMetaData);

static const struct AtChops
{
  AtEncryptionResult (*decryptBytes)(uint8_t *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);
  AtEncryptionResult (*decryptString)(char *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);

  AtEncryptionResult (*encryptBytes)(uint8_t *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);
  AtEncryptionResult (*encryptString)(char *data, size_t dataLen, AtEncryptionMetaData atEncryptionMetaData);

  char *(*hash)(uint8_t *signedData, size_t signedDataLen, AtHashingAlgorithm atHashingAlgorithm);

  AtSigningResult (*signBytes)(uint8_t data, size_t dataLen, AtSigningMetaData atSigningMetaData);
  AtSigningResult (*signString)(char *data, size_t dataLen, AtSigningMetaData atSigningMetaData);

  AtSigningResult (*verifySignatureBytes)(uint8_t *data, size_t dataLen, AtSigningMetaData atSigningMetaData);
  AtSigningResult (*verifySignatureString)(char *data, size_t dataLen, AtSigningMetaData atSigningMetaData);
} = {
    AtChops_decryptBytes,
    AtChops_decryptString,
    AtChops_encryptBytes,
    AtChops_encryptString,
    AtChops_hash,
    AtChops_signBytes,
    AtChops_signString,
    AtChops_verifySignatureBytes,
    AtChops_verifySignatureString,
};
