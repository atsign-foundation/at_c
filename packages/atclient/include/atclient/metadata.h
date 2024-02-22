
#ifndef ATCLIENT_METADATA_H
#define ATCLIENT_METADATA_H

#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DATE_STR_BUFFER_SIZE 256 // can hold most date strings found in metadata
#define GENERAL_BUFFER_SIZE 8192 // can hold most metadata strings

typedef struct atclient_atkey_metadata {
  // Represents the atSign who created this atkey.
  // This field is read from protocol string only and is not meant to be written to by the developer.
  // This field is read by the protocol and populated by the SDK for the developer to read from only.
  atclient_atsign createdby;

  // Represents the atSign who last updated this atkey.
  // This field is read from protocol string only and is not meant to be written to by the developer.
  // This field is read by the protocol and populated by the SDK for the developer to read from only.
  atclient_atsign updatedby; // repreesnts the atSign who last updated this atkey. read from protocol string only

  // TODO: info about this metadata
  // This field is read from protocol string only and is not meant to be written to by the developer.
  // This field is read by the protocol and populated by the SDK for the developer to read from only.
  atclient_atstr status;

  // TODO: info about this metadata
  // This field is read from protocol string only and is not meant to be written to by the developer.
  // This field is read by the protocol and populated by the SDK for the developer to read from only.
  int version;

  // Date and time represents when the atkey will expire at (in UTC date/time format).
  // This field is derived from the [ttl] value. If the ttl value does not exist, then this field should not exist
  // either. This field is read from protocol string only and is not meant to be written to by the developer.
  // This field is read by the protocol and populated by the SDK for the developer to read from only.
  atclient_atstr expiresat;

  // Date and time representing when the atkey will be available at (in UTC date/time format).
  // This field is derived from the [ttb] value. If the ttr value does not exist, then this field should not exist
  // either. This field is read from protocol string only and is not meant to be written to by the developer.
  // This field is read by the protocol and populated by the SDK for the developer to read from only.
  atclient_atstr availableat;

  // Date and time repreesnts when the atkey will refresh at (in UTC date/time format).
  // This field is derived from the [ttr] value. If the ttr value does not exist, then this field should not exist
  // either. This field is read from protocol string only and is not meant to be written to by the developer.
  // This field is read by the protocol and populated by the SDK for the developer to read from only.
  atclient_atstr refreshat;

  // Date and time representing when the atkey was created at (in UTC date/time format).
  // This field is read from protocol string only and is not meant to be written to by the developer.
  // this field is read by the protocol and populated by the SDK for the developer to read from only.
  atclient_atstr createdat;

  // Date and time representing when the atkey was last updated at (in UTC date/time format).
  // This field is read from protocol string only and is not meant to be written to by the developer.
  // This field is read by the protocol and populated by the SDK for the developer to read from only.
  atclient_atstr updatedat; // date and time representing when the key was last updated, read only

  // TODO: info about this metadata
  // ispublic=true means this key is accessible by all atSigns and contains non-encrypted data.
  // ispublic=false means this key is only accessible by either sharedWith or sharedBy
  // This field is not written to the protocol string by the SDK. It is a strictly client-side metadata.
  bool ispublic : 1;

  // TODO: info about this metadata
  // This field is not written to the protocol string by the SDK. It is a strictly client-side metadata.
  bool ishidden : 1;

  // iscached=true means the key contains 'cached:', written and used by client SDK only, not written to protocol string
  // iscached=false means the key does not contain 'cached:'
  // This field is not written to the protocol string by the SDK. It is a strictly client-side metadata.
  bool iscached : 1;

  // Time to live in milliseconds.
  // Represents the amount of time for atkey to exist from the point at birth to the point at death.
  // Example ttl=86400 means the atkey will live for a day.
  // This field is read from protocol string and and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  long ttl;

  // Time to birth in milliseconds
  // Represents the amount of time it takes for atkey to exist.
  // Example ttb=100 means the atkey will take 100 milliseconds to exist from the point the protocol command was sent
  // and received by the atServer
  // This field is read from protocol string and and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  long ttb;

  // Time to refresh in milliseconds
  // Represents the amount of time the cached shared atkey will refresh and update to the latest data stored by the
  // atkey in the owner of the atkey's atServer. A ttr of -1 means corresponding cached keys will not be refreshed and
  // can be cached forever. 0 means do not refresh. ttr > 0 means refresh the key every ttr milliseconds. ttr null means
  // a ttr is not applicable to this type of atkey (because it may be a selfkey), which has the same effect as 0.
  // This field is read from protocol string and and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  long ttr;

  // Cascade Delete
  // ccd=1 means this cached keys will be deleted upon the deletion of the original copy
  // ccd=0 means this cached keys will not be deleted upon the deletion of the original copy
  // This field is read from protocol string and and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  bool ccd : 1;

  // isbinary=true means atkey stores binary data
  // isbinary=false means atkey stores non-binary data (like plain text)
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  bool isbinary : 1; // (1) => key points to binary data, (0) => otherwise, writeable

  // isencrypted=true means the value is encrypted, most commonly used for sharedkeys
  // isencrypted=false means the value is not encrypted
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  bool isencrypted : 1;

  // Public data is signed using the key owner's encryptPrivateKey and the result is stored here. This is to ensure that
  // the data came from the owner of the public/private keypair
  // This field is read from protocol string and can also be set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr datasignature;

  // Represents the status of the shared key.
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr sharedkeystatus;

  // Stores the sharedkey that the data is encrypted with. This is only set if sharedWith is set. The contents will be
  // encrypted using the public key of the sharedWith atSign.
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr sharedkeyenc;

  // Regarding the following 2 fields...
  // The pubkey pair stores the hash of the encryption public key used to encrypt the [sharedKeyEnc]. The hash is used
  // to verify whether tethe current atsign's public key used for encrypting the data by another atSign, has changed
  // while decrypting the data. Both of the following fields should be used together (one without the other should not
  // happen).

  // The hash of the public key used to encrypt the [sharedKeyEnc].
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr pubkeyhash;

  // The algorithm used to hash the public key used to encrypt the [sharedKeyEnc] (e.g. "sha256" or "sha512")
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr pubkeyalgo;

  // The type of encoding the value is (e.g. "base64")
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr encoding;

  // The name of the key used to encrypt the value. If not provided, use sharedKeyEnc in the metadata. If sharedKeyEnc
  // is not provided, use the default shared key. If enckeyname is provided, just the key name must be provided example
  // without the sharedWith suffix and sharedBy prefix, nor visibility prefix. Example '@bob:shared_key.wavi@alice',
  // must be only be 'shared_key.wavi'
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr enckeyname;

  // The name of the algorithm used to encrypt the value. For data, the default algorithm is 'AES/SIC/PKCS7Padding', for
  // cryptographic keys, the default algorithm is 'RSA'
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr encalgo;

  // The initialization vector or nonce used when the data was encrypted with the shared symmetric encryption key
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr ivnonce;

  // TODO: info about this metadata
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr skeenckeyname;

  // TODO: info about this metadata
  // This field is read from protocol string and set by the developer.
  // This field is written to protocol string by the SDK. (See atclient_atkey_metadata_to_protocolstr)
  atclient_atstr skeencalgo;

  // Holds the metadata fields that have not been initialized (0) or have been initialized (1)
  uint8_t initializedfields[3];
} atclient_atkey_metadata;

/**
 * @brief initializes the atkey metadata struct. You should call this function before using any subsequent
 * atkey_metadata_ functions.
 *
 * @param metadata the atkey metadata struct to initialize. It is assumed that this struct has not yet been initialized
 */
void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata);

/**
 * @brief Populates the metadata struct from a string. This function is good for debugging.
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
 * @brief Reads metadata struct and converts it to a json formatted string. This function should mostly be used for
 * debugging only. See atclient_atkey_metadata_to_protocolstr for a more useful function when working with atProtocol
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

bool atclient_atkey_metadata_is_createdby_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_updatedby_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_status_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_version_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_expiresat_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_availableat_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_refreshat_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_createdat_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_updatedat_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_ispublic_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_ishidden_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_iscached_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_ttl_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_ttb_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_ttr_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_ccd_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_isbinary_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_isencrypted_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_datasignature_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_sharedkeystatus_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_sharedkeyenc_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_pubkeyhash_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_pubkeyalgo_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_encoding_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_enckeyname_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_encalgo_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_ivnonce_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_skeenckeyname_initialized(const atclient_atkey_metadata metadata);
bool atclient_atkey_metadata_is_skeencalgo_initialized(const atclient_atkey_metadata metadata);

/**
 * @brief frees the metadata struct's variables that were allocated in the atclient_atkey_metadata_init function.
 *
 * @param metadata the metadata struct that contains allocated memory that needs to be freed
 */
void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata);

#endif
