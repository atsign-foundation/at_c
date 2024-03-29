
#ifndef ATCLIENT_METADATA_H
#define ATCLIENT_METADATA_H

#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include "cJSON/cJSON.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h> // IWYU pragma: keep (for uint8_t)

#define VALUE_INITIALIZED 0b00000001

// initializedfields[0]
#define ATKEY_METADATA_CREATEDBY_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATKEY_METADATA_UPDATEDBY_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATKEY_METADATA_STATUS_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATKEY_METADATA_VERSION_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATKEY_METADATA_EXPIRESAT_INITIALIZED (VALUE_INITIALIZED << 4)
#define ATKEY_METADATA_AVAILABLEAT_INITIALIZED (VALUE_INITIALIZED << 5)
#define ATKEY_METADATA_REFRESHAT_INITIALIZED (VALUE_INITIALIZED << 6)
#define ATKEY_METADATA_CREATEDAT_INITIALIZED (VALUE_INITIALIZED << 7)

// initializedfields[1]
#define ATKEY_METADATA_UPDATEDAT_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATKEY_METADATA_ISPUBLIC_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATKEY_METADATA_ISHIDDEN_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATKEY_METADATA_ISCACHED_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATKEY_METADATA_TTL_INITIALIZED (VALUE_INITIALIZED << 4)
#define ATKEY_METADATA_TTB_INITIALIZED (VALUE_INITIALIZED << 5)
#define ATKEY_METADATA_TTR_INITIALIZED (VALUE_INITIALIZED << 6)
#define ATKEY_METADATA_CCD_INITIALIZED (VALUE_INITIALIZED << 7)

// initializedfields[2]
#define ATKEY_METADATA_ISBINARY_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATKEY_METADATA_ISENCRYPTED_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATKEY_METADATA_DATASIGNATURE_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATKEY_METADATA_SHAREDKEYSTATUS_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATKEY_METADATA_SHAREDKEYENC_INITIALIZED (VALUE_INITIALIZED << 4)
#define ATKEY_METADATA_PUBKEYHASH_INITIALIZED (VALUE_INITIALIZED << 5)
#define ATKEY_METADATA_PUBKEYALGO_INITIALIZED (VALUE_INITIALIZED << 6)
#define ATKEY_METADATA_ENCODING_INITIALIZED (VALUE_INITIALIZED << 7)

// initializedfields[3]
#define ATKEY_METADATA_ENCKEYNAME_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATKEY_METADATA_ENCALGO_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATKEY_METADATA_IVNONCE_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATKEY_METADATA_SKEENCKEYNAME_INITIALIZED (VALUE_INITIALIZED << 3)
#define ATKEY_METADATA_SKEENCALGO_INITIALIZED (VALUE_INITIALIZED << 4)

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
  bool iscached : 1;
  // This field is not written to the protocol string by the SDK. It is a strictly client-side metadata.

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
  bool isbinary : 1;

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
  uint8_t initializedfields[4];
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
 * @brief Populates the metadata struct from a cJSON pointer. This function is good for debugging.
 *
 * @param metadata the metadata struct to populate
 * @param json the json object to populate from
 */
void atclient_atkey_metadata_from_cjson_node(atclient_atkey_metadata *metadata, const cJSON *json);
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
int atclient_atkey_metadata_to_jsonstr(const atclient_atkey_metadata *metadata, char *metadatastr,
                                       const size_t metadatastrlen, size_t *metadatastrolen);

size_t atclient_atkey_metadata_protocol_strlen(const atclient_atkey_metadata *metadata);
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
int atclient_atkey_metadata_to_protocol_str(const atclient_atkey_metadata *metadata, char *metadatastr,
                                            const size_t metadatastrlen, size_t *metadatastrolen);

bool atclient_atkey_metadata_is_createdby_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_updatedby_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_status_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_version_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_expiresat_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_availableat_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_refreshat_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_createdat_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_updatedat_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_ispublic_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_ishidden_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_iscached_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_ttl_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_ttb_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_ttr_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_ccd_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_isbinary_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_isencrypted_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_datasignature_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_sharedkeystatus_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_sharedkeyenc_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_pubkeyhash_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_pubkeyalgo_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_encoding_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_enckeyname_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_encalgo_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_ivnonce_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_skeenckeyname_initialized(const atclient_atkey_metadata *metadata);
bool atclient_atkey_metadata_is_skeencalgo_initialized(const atclient_atkey_metadata *metadata);

size_t atclient_atkey_metadata_createdby_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_updatedby_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_status_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_version_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_expiresat_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_availableat_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_refreshat_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_createdat_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_updatedat_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_ispublic_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_ishidden_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_iscached_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_ttl_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_ttb_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_ttr_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_ccd_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_isbinary_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_isencrypted_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_datasignature_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_sharedkeystatus_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_sharedkeyenc_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_pubkeyhash_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_pubkeyalgo_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_encoding_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_enckeyname_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_encalgo_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_ivnonce_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_skeenckeyname_strlen(const atclient_atkey_metadata *metadata);
size_t atclient_atkey_metadata_skeencalgo_strlen(const atclient_atkey_metadata *metadata);

void atclient_atkey_metadata_set_ispublic(atclient_atkey_metadata *metadata, const bool ispublic);
void atclient_atkey_metadata_set_ishidden(atclient_atkey_metadata *metadata, const bool ishidden);
void atclient_atkey_metadata_set_iscached(atclient_atkey_metadata *metadata, const bool iscached);
void atclient_atkey_metadata_set_ttl(atclient_atkey_metadata *metadata, const long ttl);
void atclient_atkey_metadata_set_ttb(atclient_atkey_metadata *metadata, const long ttb);
void atclient_atkey_metadata_set_ttr(atclient_atkey_metadata *metadata, const long ttr);
void atclient_atkey_metadata_set_ccd(atclient_atkey_metadata *metadata, const bool ccd);
void atclient_atkey_metadata_set_isbinary(atclient_atkey_metadata *metadata, const bool isbinary);
void atclient_atkey_metadata_set_isencrypted(atclient_atkey_metadata *metadata, const bool isencrypted);

int atclient_atkey_metadata_set_datasignature(atclient_atkey_metadata *metadata, const char *datasignature,
                                              const size_t datasignaturelen);

int atclient_atkey_metadata_set_sharedkeystatus(atclient_atkey_metadata *metadata, const char *sharedkeystatus,
                                                const size_t sharedkeystatuslen);

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
