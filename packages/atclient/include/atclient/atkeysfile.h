#ifndef ATCLIENT_ATKEYSFILE_H
#define ATCLIENT_ATKEYSFILE_H

#include <stddef.h>
#include <stdint.h>

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_ATKEYSFILE_AESPKAMPUBLICKEYSTR_INDEX 0
#define ATCLIENT_ATKEYSFILE_AESPKAMPRIVATEKEYSTR_INDEX 0
#define ATCLIENT_ATKEYSFILE_AESENCRYPTPUBLICKEYSTR_INDEX 0
#define ATCLIENT_ATKEYSFILE_AESENCRYPTPRIVATEKEYSTR_INDEX 0
#define ATCLIENT_ATKEYSFILE_SELFENCRYPTIONKEYSTR_INDEX 0

#define ATCLIENT_ATKEYSFILE_AESPKAMPUBLICKEYSTR_INTIIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_ATKEYSFILE_AESPKAMPRIVATEKEYSTR_INTIIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_ATKEYSFILE_AESENCRYPTPUBLICKEYSTR_INTIIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_ATKEYSFILE_AESENCRYPTPRIVATEKEYSTR_INTIIALIZED (VALUE_INITIALIZED << 3)
#define ATCLIENT_ATKEYSFILE_SELFENCRYPTIONKEYSTR_INTIIALIZED (VALUE_INITIALIZED << 4)

typedef struct atclient_atkeysfile {
  char *aespkampublickeystr; // encrypted with self encryption key. AES decryption with self encryption key will reveal base64-encoded RSA key
  char *aespkamprivatekeystr; // encrypted with self encryption key. AES decryption with self encryption key will reveal base64-encoded RSA keyF
  char *aesencryptpublickeystr; // encrypted with self encryption key. AES decryption with self encryption key will reveal base64-encoded RSA key
  char *aesencryptprivatekeystr; // encrypted with self encryption key. AES decryption with self encryption key will reveal base64-encoded RSA key
  char *selfencryptionkeystr; // base64-encoded non-encrypted self encryption key. base64 decoding will reveal 32-byte AES key
  uint8_t _initializedfields[1];
} atclient_atkeysfile;

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile);
int atclient_atkeysfile_read(atclient_atkeysfile *atkeysfile, const char *path);
void atclient_atkeysfile_free(atclient_atkeysfile *atkeysfile);

#endif
