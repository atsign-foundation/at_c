#include "at_chops.h"

#ifdef BUILD_ESP_IDF

// Encryption and Decryption - AES
void decryptBytes_AES(uint8_t *data, size_t dataLen, AtEncryptionKey *key, InitialisationVector *iv);
void decryptString_AES(char *data, size_t dataLen, AtEncryptionKey *key, InitialisationVector *iv);
void encryptBytes_AES(uint8_t *data, size_t dataLen, AtEncryptionKey *key);
void encryptString_AES(char *data, size_t dataLen, AtEncryptionKey *key);

// Encryption and Decryption - ECC
void decryptBytes_ECC(uint8_t *data, size_t dataLen, AtEncryptionKey *key, InitialisationVector *iv);
void decryptString_ECC(char *data, size_t dataLen, AtEncryptionKey *key, InitialisationVector *iv);
void encryptBytes_ECC(uint8_t *data, size_t dataLen, AtEncryptionKey *key);
void encryptString_ECC(char *data, size_t dataLen, AtEncryptionKey *key);

// Encryption and Decryption - RSA
void decryptBytes_RSA(uint8_t *data, size_t dataLen, AtEncryptionKey *key);
void decryptString_RSA(char *data, size_t dataLen, AtEncryptionKey *key);
void encryptBytes_RSA(uint8_t *data, size_t dataLen, AtEncryptionKey *key);
void encryptString_RSA(char *data, size_t dataLen, AtEncryptionKey *key);

// Hashing
char *hash_MD5(uint8_t *signedData, size_t signedDataLen);
char *hash_SHA512(uint8_t *signedData, size_t signedDataLen);

// Signing and Verification - RSA/SHA256
void signBytes_RSA_SHA256(uint8_t data, size_t dataLen, AtEncryptionKey *key);
void signString_RSA_SHA256(char *data, size_t dataLen, AtEncryptionKey *key);
void verifySignatureBytes_RSA_SHA256(uint8_t *data, size_t dataLen, uint8_t *signature, size_t signatureLen, AtEncryptionKey *key);
void verifySignatureString_RSA_SHA256(char *data, size_t dataLen, char *signature, size_t signatureLen, AtEncryptionKey *key);

#endif
