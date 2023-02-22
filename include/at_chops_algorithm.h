#pragma once

#include "at_chops_type.h"

// Developer notes
// The original dart implementation uses the strategy pattern to implement the algorithms.
// This is not possible in C because of the lack of interfaces,
// thus we use a struct with function pointers to represent a covariant interface.
// We use a union to represent the generic type of the algorithm.

typedef union EncryptionAlgorithm
{
  AtEncryptionAlgorithm atEncryptionAlgorithm;
  SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm;
  AtSigningAlgorithm atSigningAlgorithm;
  AtHashingAlgorithm atHashingAlgorithm;
} EncryptionAlgorithm;

typedef struct AtEncryptionAlgorithm
{
  uint8_t *(*encrypt)(uint8_t *plainData, size_t plainDataLen);
  uint8_t *(*decrypt)(uint8_t *encryptedData, size_t encryptedDataLen);
} AtEncryptionAlgorithm;

typedef struct SymmetricEncryptionAlgorithm
{
  uint8_t *(*encrypt)(uint8_t *plainData, size_t plainDataLen);
  uint8_t *(*encrypt)(uint8_t *plainData, size_t plainDataLen, InitialisationVector iv);

  uint8_t *(*decrypt)(uint8_t *encryptedData, size_t encryptedDataLen);
  uint8_t *(*decrypt)(uint8_t *encryptedData, size_t encryptedDataLen, InitialisationVector iv);
} SymmetricEncryptionAlgorithm;

typedef struct AtSigningAlgorithm
{
  uint8_t *(*sign)(uint8_t *data);
  bool (*verify)(uint8_t *signedData, uint8_t *signature);
} AtSigningAlgorithm;

typedef struct AtHashingAlgorithm
{
  char *(*hash)(uint8_t *data);
} AtHashingAlgorithm;
