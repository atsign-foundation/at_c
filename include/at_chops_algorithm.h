#pragma once

#include "at_chops_type.h"
#include <stdbool.h>

// Developer notes
// The original dart implementation uses the strategy pattern to implement the algorithms.
// This is not possible in C because of the lack of interfaces,
// thus we use a struct with function pointers to represent a covariant interface.
// We use a union to represent the generic type of the algorithm.

namespace AtChopsAlgorithm
{

  typedef union EncryptionAlgorithm
  {
    AtEncryptionAlgorithm atEncryptionAlgorithm;
    SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm;
    AtSigningAlgorithm atSigningAlgorithm;
    AtHashingAlgorithm atHashingAlgorithm;
  } EncryptionAlgorithm;

  typedef struct AtEncryptionAlgorithm
  {
    DartType::Uint8List (*encrypt)(DartType::Uint8List plainData, size_t plainDataLen);
    DartType::Uint8List (*decrypt)(DartType::Uint8List encryptedData, size_t encryptedDataLen);
  } AtEncryptionAlgorithm;

  typedef struct SymmetricEncryptionAlgorithm
  {
    DartType::Uint8List (*encrypt)(DartType::Uint8List plainData, size_t plainDataLen);
    DartType::Uint8List (*encrypt)(DartType::Uint8List plainData, size_t plainDataLen, AtChopsType::InitialisationVector iv);

    DartType::Uint8List (*decrypt)(DartType::Uint8List encryptedData, size_t encryptedDataLen);
    DartType::Uint8List (*decrypt)(DartType::Uint8List encryptedData, size_t encryptedDataLen, AtChopsType::InitialisationVector iv);
  } SymmetricEncryptionAlgorithm;

  typedef struct AtSigningAlgorithm
  {
    DartType::Uint8List sign(DartType::Uint8List data);
    bool verify(DartType::Uint8List signedData, DartType::Uint8List signature);
  } AtSigningAlgorithm;

  typedef struct AtHashingAlgorithm
  {
    DartType::String hash(DartType::Uint8List data);
  } AtHashingAlgorithm;
}
