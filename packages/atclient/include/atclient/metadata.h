
#ifndef METADATA_H
#define METADATA_H

#include "atclient/atsign.h"

typedef struct atclient_atkey_metadata_date_entry
{
    unsigned long datestrlen;
    char *datestr;
    unsigned long datestrolen;
} atclient_atkey_metadata_date_entry;

typedef struct atclient_atkey_metadata_str
{
    unsigned long datestrlen;
    char *datestr;
    unsigned long datestrolen;
} atclient_atkey_metadata_str;

typedef struct atclient_atkey_metadata
{
    atclient_atsign createdby; // read and set by the protocol
    atclient_atsign updatedby; // read and set by the protocol
    atclient_atkey_metadata_date_entry createdat; // date representing when key was created
    atclient_atkey_metadata_date_entry updatedat; // date representing when key was last modified
    atclient_atkey_metadata_str *status;
    atclient_atkey_metadata_str *datasignature; // public data is signed using the key owner's encryptPrivateKey and result is stored here
    int version; // read and set by the protocol
    unsigned long ttl; // time to live in milliseconds
    unsigned long ttb; // time to birth in milliseconds
    unsigned long ttr; // time to refresh. -1 means corresponding cached keys will not be refreshed and can be cached forever, 0 means do not refresh, ttr > 0 means refresh the key every ttr milliseconds, ttr null means it is non-applicable (aka this key cannot be cached) which has the same effect as 0
    int ccd; // cascade delete; (1) => cached key will be deleted upon the deletion of this key, (0) => no cascade delete
    int isbinary; // (1) => key points to binary data, (0) => otherwise
    int isencrypted; // (1) => key points to value is encrypted
    atclient_atkey_metadata_str *sharedkeyenc; // stores the shared key that the data is encrypted with. this is only set if sharedWith is set. the contents will be encrypted using the public key of the sharedWith atSign
    atclient_atkey_metadata_str *pubkeycs; // public key checksum. Stores the checksum of the encryption public key used to encrypt the [sharedkeyenc]. We use this to verify that the encryption keypair used to encrypt and decrypt the value are teh same
    atclient_atkey_metadata_str *ivnonce; // Initialization vector or nonce used when the data was encrypted with the shared symmetric encryption key
    atclient_atkey_metadata_str *enckeyname; // the name of the key used to encrypt the value. If not provided, use sharedKeyEnc in the metadata. If sharedKeyEnc is not provided, use the default shared key. If enckeyname is provided, just the key name must be provided example without the sharedWith suffix and sharedBy prefix, nor visibility prefix. Example '@bob:shared_key.wavi@alice', must be only be 'shared_key.wavi'
    atclient_atkey_metadata_str *encalgo; // name of the algorithm used to encrypt the value. For data, the default algorithm is 'AES/SIC/PKCS7Padding', for cryptographic keys, the default algorithm is 'RSA'
    atclient_atkey_metadata_str *skeenckeyname;
    atclient_atkey_metadata_str *skeencalgo;


    // derived fields
    atclient_atkey_metadata_date_entry availableat; // derived field via [ttb]
    atclient_atkey_metadata_date_entry expiresat; // derived field via [ttl]
    atclient_atkey_metadata_date_entry refreshat; // derived field via [ttr]
    int iscached; // (1) means key contains 'cached:'
    int ispublic; // contains public:. if true (1), then this key is accessible by all atSigns and contains non-encrypted data. if false (0), then it is only accessible by either sharedWith or sharedBy
    int ishidden; // (1) => key begins with '_', (0) otherwise
} atclient_atkey_metadata;

void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata);
int atclient_atkey_metadata_from_string(atclient_atkey_metadata *metadata, const char *metadatastr, const unsigned long metadatastrlen);
void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata);

#endif