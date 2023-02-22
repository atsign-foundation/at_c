#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint8_t
#include <stdbool.h> // bool

typedef struct
{
  size_t vecLen;
  uint8_t vec[];
} InitialisationVector;

typedef enum
{
  rsa2048,
  rsa4096,
  ecc,
  aes128,
  aes192,
  aes256
} EncryptionKeyType;

typedef struct
{
  EncryptionKeyType keyType;
  size_t keyLen;
  char key[];
} AtEncryptionKey;

// Encryption and Decryption - AES
extern void decryptBytes_AES(uint8_t *data, size_t dataLen, AtEncryptionKey *key, InitialisationVector *iv);
extern void decryptString_AES(char *data, size_t dataLen, AtEncryptionKey *key, InitialisationVector *iv);
extern void encryptBytes_AES(uint8_t *data, size_t dataLen, AtEncryptionKey *key);
extern void encryptString_AES(char *data, size_t dataLen, AtEncryptionKey *key);

// Encryption and Decryption - ECC
extern void decryptBytes_ECC(uint8_t *data, size_t dataLen, AtEncryptionKey *key, InitialisationVector *iv);
extern void decryptString_ECC(char *data, size_t dataLen, AtEncryptionKey *key, InitialisationVector *iv);
extern void encryptBytes_ECC(uint8_t *data, size_t dataLen, AtEncryptionKey *key);
extern void encryptString_ECC(char *data, size_t dataLen, AtEncryptionKey *key);

// Encryption and Decryption - RSA
extern void decryptBytes_RSA(uint8_t *data, size_t dataLen, AtEncryptionKey *key);
extern void decryptString_RSA(char *data, size_t dataLen, AtEncryptionKey *key);
extern void encryptBytes_RSA(uint8_t *data, size_t dataLen, AtEncryptionKey *key);
extern void encryptString_RSA(char *data, size_t dataLen, AtEncryptionKey *key);

// Hashing
extern char *hash_MD5(uint8_t *signedData, size_t signedDataLen);
extern char *hash_SHA512(uint8_t *signedData, size_t signedDataLen);

// Signing and Verification - RSA/SHA256
extern void signBytes_RSA_SHA256(uint8_t data, size_t dataLen, AtEncryptionKey *key);
extern void signString_RSA_SHA256(char *data, size_t dataLen, AtEncryptionKey *key);
extern void verifySignatureBytes_RSA_SHA256(uint8_t *data, size_t dataLen, uint8_t *signature, size_t signatureLen, AtEncryptionKey *key);
extern void verifySignatureString_RSA_SHA256(char *data, size_t dataLen, char *signature, size_t signatureLen, AtEncryptionKey *key);
