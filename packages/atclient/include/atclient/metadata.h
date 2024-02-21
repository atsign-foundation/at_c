
#ifndef ATCLIENT_METADATA_H
#define ATCLIENT_METADATA_H

#include "atclient/atstr.h"
#include <stdbool.h>
#include <stddef.h>

#define DATE_STR_BUFFER_SIZE 256 // can hold most date strings found in metadata
#define GENERAL_BUFFER_SIZE 8192 // can hold most metadata strings

typedef struct atclient_atkey_metadata {
  atclient_atstr createdby; // represents the atSign who created this atkey. read from protoocl string
  atclient_atstr updatedby; // repreesnts the atSign who last updated this atkey. read from protocol string only
  atclient_atstr status;    // read from protocol string only
  int version;              // read from protocol string
  long ttl;                 // time to live in milliseconds, written to protocol string
  long ttb;                 // time to birth in milliseconds, written to protocol string
  long ttr; // time to refresh. -1 means corresponding cached keys will not be refreshed and can be cached
            // forever, 0 means do not refresh, ttr > 0 means refresh the key every ttr milliseconds, ttr null
            // means it is non-applicable (aka this key cannot be cached) which has the same effect as 0, writeable
  bool ccd; // cascade delete; (1) => cached key will be deleted upon the deletion of this key, (0) => no cascade
            // delete, writeable
  // derived fields
  atclient_atstr availableat;     // derived field via [ttb], read only
  atclient_atstr expiresat;       // derived field via [ttl], read only
  atclient_atstr refreshat;       // derived field via [ttr], read only
  atclient_atstr createdat;       // date and time representing when the key was created, read only
  atclient_atstr updatedat;       // date and time representing when the key was last updated, read only
  atclient_atstr datasignature;   // public data is signed using the key owner's encryptPrivateKey and result is stored
                                  // here, writeable
  atclient_atstr sharedkeystatus; // represents status of the [SharedKey], writeable
  bool ispublic; // contains public:. if true (1), then this key is accessible by all atSigns and contains non-encrypted
                 // data. if false (0), then it is only accessible by either sharedWith or sharedBy, is written and used
                 // by client SDK only, not written to protocol string
  bool ishidden; // (1) => key begins with '_', (0) otherwise, written and used by client SDK only, not written to
                 // protocol string
  bool isbinary; // (1) => key points to binary data, (0) => otherwise, writeable
  bool isencrypted; // (1) => key points to value is encrypted, writeable
  bool
      iscached; // (1) means key contains 'cached:', written and used by client SDK only, not written to protocol string
  atclient_atstr sharedkeyenc; // stores the shared key that the data is encrypted with. this is only set if sharedWith
                               // is set. the contents will be encrypted using the public key of the sharedWith atSign
  // The pubkey pair stores the hash of the encryption public key used to encrypt the [sharedKeyEnc]. The hash is used
  // to verify whether tethe current atsign's public key used for encrypting the data by another atSign, has changed
  // while decrypting the data. Both of the following fields should be used together (one without the other should not
  // happen)., writeable
  atclient_atstr pubkeyhash; // the hash of the public key used to encrypt the [sharedKeyEnc], writeable
  atclient_atstr pubkeyalgo; // the algorithm used to hash the public key used to encrypt the [sharedKeyEnc] (e.g.
                             // \"sha256\" or \"sha512\"), writeable

  atclient_atstr encoding; // type of encoding the value is (e.g. \"base64\"), writeable

  atclient_atstr
      enckeyname; // the name of the key used to encrypt the value. If not provided, use sharedKeyEnc in the metadata.
                  // If sharedKeyEnc is not provided, use the default shared key. If enckeyname is provided, just the
                  // key name must be provided example without the sharedWith suffix and sharedBy prefix, nor visibility
                  // prefix. Example '@bob:shared_key.wavi@alice', must be only be 'shared_key.wavi', writeable
  atclient_atstr encalgo; // name of the algorithm used to encrypt the value. For data, the default algorithm is
                          // 'AES/SIC/PKCS7Padding', for cryptographic keys, the default algorithm is 'RSA', writeable
  atclient_atstr ivnonce; // Initialization vector or nonce used when the data was encrypted with the shared symmetric
                          // encryption key, writeable
  atclient_atstr skeenckeyname; // , writeable
  atclient_atstr skeencalgo;    // , writeable
} atclient_atkey_metadata;

/**
 * @brief initializes the atkey metadata struct. You should call this function before using any subsequent
 * atkey_metadata_ functions.
 *
 * @param metadata the atkey metadata struct to initialize. It is assumed that this struct has not yet been initialized
 */
void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata);

/**
 * @brief populates the metadata struct from a string.
 *
 * @param metadata the metadata struct to populate
 * @param metadatastr the metadata string (usually taken from meta commands such as llookup:meta:<atkey> or
 * plookup:meta:<atkey<)
 * @param metadatastrlen the string length of the metadata string. Can be obtained from something like
 * strlen(metadatastr)
 * @return int 0 on success
 */
int atclient_atkey_metadata_from_jsonstr(atclient_atkey_metadata *metadata, const char *metadatastr,
                                         const size_t metadatastrlen);

/**
 * @brief reads metadata struct and converts it to a json formatted string
 *
 * @param metadata the metadata struct to convert to a string
 * @param metadatastr the buffer to write the metadata to
 * @param metadatastrlen the allocated length of the metadatastr buffer
 * @param metadatastrolen the length of the metadata string written to metadatastr once the operation is complete
 * @return int 0 on success
 */
int atclient_atkey_metadata_to_jsonstr(const atclient_atkey_metadata metadata, char *metadatastr,
                                       const size_t metadatastrlen, size_t *metadatastrolen);

/**
 * @brief Creates a fragment which can be included in any atProtocol commands which use metadata (e.g. update,
 * update:meta and notify)
 *
 * @param metadata the metadata struct to read from
 * @param metadatastr the buffer to write the metadata to
 * @param metadatastrlen the allocated length of the metadatastr buffer
 * @param metadatastrolen the length of the metadata string written to metadatastr once the operation is complete
 * @return int 0 on success
 */
int atclient_atkey_metadata_to_protocolstr(const atclient_atkey_metadata metadata, char *metadatastr,
                                           const size_t metadatastrlen, size_t *metadatastrolen);

int atclient_atkey_metadata_set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature,
                                              const size_t datasignaturelen);

int atclient_atkey_metadata_set_ttl(atclient_atkey_metadata *metadata, const long ttl);

int atclient_atkey_metadata_set_ttb(atclient_atkey_metadata *metadata, const long ttb);

int atclient_atkey_metadata_set_ttr(atclient_atkey_metadata *metadata, const long ttr);

int atclient_atkey_metadata_set_ccd(atclient_atkey_metadata *metadata, const bool ccd);

int atclient_atkey_metadata_set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature,
                                              const size_t datasignaturelen);

int atclient_atkey_metadata_set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus,
                                                const size_t sharedkeystatuslen);
int atclient_atkey_metadata_set_ispublic(atclient_atkey_metadata *metadata, const bool ispublic);

int atclient_atkey_metadata_set_isbinary(atclient_atkey_metadata *metadata, const bool isbinary);

int atclient_atkey_metadata_set_isencrypted(atclient_atkey_metadata *metadata, const bool isencrypted);

int atclient_atkey_metadata_set_iscached(atclient_atkey_metadata *metadata, const bool iscached);

int atclient_atkey_metadata_set_sharedkeyenc(atclient_atkey_metadata *metadata, const char *sharedkeyenc,
                                             const size_t sharedkeyenclen);

int atclient_atkey_metadata_set_pubkeyhash(atclient_atkey_metadata *metadata, const char *pubkeyhash,
                                           const size_t pubkeyhashlen);

int atclient_atkey_metadata_set_pubkeyalgo(atclient_atkey_metadata *metadata, const char *pubkeyalgo,
                                           const size_t pubkeyalgolen);

int atclient_atkey_metadata_set_encoding(atclient_atkey_metadata *metadata, const char *encoding,
                                         const size_t encodinglen);

int atclient_atkey_metadata_set_enckeyname(atclient_atkey_metadata *metadata, const char *enckeyname,
                                           const size_t enckeynamelen);

int atclient_atkey_metadata_set_encalgo(atclient_atkey_metadata *metadata, const char *encalgo,
                                        const size_t encalgolen);

int atclient_atkey_metadata_set_ivnonce(atclient_atkey_metadata *metadata, const char *ivnonce,
                                        const size_t ivnoncelen);

int atclient_atkey_metadata_set_skeenckeyname(atclient_atkey_metadata *metadata, const char *skeenckeyname,
                                              const size_t skeenckeynamelen);

int atclient_atkey_metadata_set_skeencalgo(atclient_atkey_metadata *metadata, const char *skeencalgo,
                                           const size_t skeencalgolen);

/**
 * @brief frees the metadata struct's variables that were allocated in the atclient_atkey_metadata_init function.
 *
 * @param metadata the metadata struct that contains allocated memory that needs to be freed
 */
void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata);

#endif
