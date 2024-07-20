#ifndef ATCLIENT_ATKEY_H
#define ATCLIENT_ATKEY_H

#include "atclient/metadata.h"
#include <stddef.h>
#include <stdint.h>

#define VALUE_INITIALIZED 0b00000001

#define ATKEY_KEY_INDEX 0
#define ATKEY_NAMESPACESTR_INDEX 0
#define ATKEY_SHAREDBY_INDEX 0
#define ATKEY_SHAREDWITH_INDEX 0

#define ATKEY_KEY_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATKEY_NAMESPACESTR_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATKEY_SHAREDBY_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATKEY_SHAREDWITH_INITIALIZED (VALUE_INITIALIZED << 3)

typedef enum atclient_atkey_type {
  ATCLIENT_ATKEY_TYPE_UNKNOWN = 0,
  ATCLIENT_ATKEY_TYPE_PUBLICKEY,
  ATCLIENT_ATKEY_TYPE_SELFKEY,
  ATCLIENT_ATKEY_TYPE_SHAREDKEY,
} atclient_atkey_type;

typedef struct atclient_atkey {
  char *key;
  char *namespacestr;
  char *sharedby;
  char *sharedwith;

  uint8_t _initializedfields[1]; // internal field to track which fields are allocated

  atclient_atkey_metadata metadata;

} atclient_atkey;

/**
 * @brief Initialize an atkey struct. This function should be called before any other atkey functions.
 *
 * @param atkey the atkey struct to initialize
 */
void atclient_atkey_init(atclient_atkey *atkey);

/**
 * @brief free an atkey struct. This function should be called at the end of an atkey's life
 *
 * @param atkey the atkey struct to free
 */
void atclient_atkey_free(atclient_atkey *atkey);

/**
 * @brief get the length of the atkey string
 *
 * @param atkey atkey struct to read, assumed that this was already initialized via atclient_atkey_init
 * @return size_t the length of the atkey string
 *
 * @note this excludes the null terminator and metadata string fragement
 */
size_t atclient_atkey_strlen(const atclient_atkey *atkey);

/**
 * @brief populate an atkey struct given a null terminated string. Be sure to call the atclient_atkey_init function
 * before calling this function.
 *
 * @param atkey the atkey struct to populate, assumed that this was already initialized via atclient_atkey_init
 * @param atkeystr the atkeystr to derive from (e.g. 'public:name.wavi@alice')
 * @param atkeylen the length of the atkeystr
 * @return int 0 on success, that a struct was able to be created from the string. (the string followed proper key
 * nomenclature)
 */
int atclient_atkey_from_string(atclient_atkey *atkey, const char *atkeystr);

/**
 * @brief convert an atkey struct to its string format
 *
 * @param atkey atkey struct to read, assumed that this was already initialized via atclient_atkey_init
 * @param atkeystr a double pointer to the atkey string, this will be allocated by this function and is the
 * responsibility of the caller of this function to free it
 * @return int 0 on success
 */
int atclient_atkey_to_string(const atclient_atkey *atkey, char **atkeystr);

/**
 * @brief Returns true if atkey->key is initialized and allocated, and the value is safe for reading
 *
 * @param atkey the atkey struct to read
 * @return true, if the key is initialized and allocated and is safe for reading
 * @return false, if the key is not initialized and not allocated and is not safe for reading, high chance that it holds
 * garbage
 */
bool atclient_atkey_is_key_initialized(const atclient_atkey *atkey);

/**
 * @brief Returns true if atkey->namespacestr is initialized and allocated, and the value is safe for reading
 *
 * @param atkey the atkey struct to read
 * @return true, if the namespacestr is initialized and allocated and is safe for reading
 * @return false, if the namespacestr is not initialized and not allocated and is not safe for reading, high chance that
 * it holds garbage
 */
bool atclient_atkey_is_namespacestr_initialized(const atclient_atkey *atkey);

/**
 * @brief Returns true if atkey->sharedby is initialized and allocated, and the value is safe for reading
 *
 * @param atkey the atkey struct to read
 * @return true, if the sharedby is initialized and allocated and is safe for reading
 * @return false, if the sharedby is not initialized and not allocated and is not safe for reading, high chance that it
 * holds garbage
 */
bool atclient_atkey_is_sharedby_initialized(const atclient_atkey *atkey);

/**
 * @brief Returns true if atkey->sharedwith is initialized and allocated, and the value is safe for reading
 *
 * @param atkey the atkey struct to read
 * @return true, if the sharedwith is initialized and allocated and is safe for reading
 * @return false, if the sharedwith is not initialized and not allocated and is not safe for reading, high chance that
 * it holds garbage
 */
bool atclient_atkey_is_sharedwith_initialized(const atclient_atkey *atkey);

/**
 * @brief Dynamically allocates memory and duplicates key to be stored in the atkey struct. If this is allocated, then
 * it is freed with atclient_atkey_free by the end of life of your struct
 *
 * @param atkey The atkey struct that will hold the key, assumed that this was already initialized via
 * atclient_atkey_init
 * @param key The key string, for example if my atkey is "@alice:phone.wavi@bob", then the key is "phone"
 * @return int 0 on success, otherwise error (most likely malloc error)
 */
int atclient_atkey_set_key(atclient_atkey *atkey, const char *key);

/**
 * @brief Dynamically allocates memory and duplicates namespacestr to be stored in the atkey struct. If this is
 * allocated, then it is freed with atclient_atkey_free by the end of life of your struct
 *
 * @param atkey (mandatory, NON-NULL) The atkey struct to populate, assumed that this was already initialized via
 * atclient_atkey_init
 * @param namespacestr (mandatory, NON-NULL) The namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success, otherwise error (most likely malloc error)
 */
int atclient_atkey_set_namespacestr(atclient_atkey *atkey, const char *namespacestr);

/**
 * @brief Dynamically allocates memory and duplicates sharedby to be stored in the atkey struct. If this is allocated,
 * then it is freed with atclient_atkey_free by the end of life of your struct
 *
 * @param atkey (mandatory, NON-NULL) The atkey struct to populate, assumed that this was already initialized via
 * atclient_atkey_init
 * @param sharedby (mandatory, NON-NULL) The sharedby (creator/pkam authenticated atsign) of the atkey, e.g.: "@alice"
 * @return int 0 on success, otherwise error (most likely malloc error)
 */
int atclient_atkey_set_sharedby(atclient_atkey *atkey, const char *sharedby);

/**
 * @brief Dynamically allocates memory and duplicates sharedwith to be stored in the atkey struct. If this is allocated,
 * then it is freed with atclient_atkey_free by the end of life of your struct
 *
 * @param atkey  (mandatory, NON-NULL) The atkey struct to populate, assumed that this was already initialized via
 * atclient_atkey_init
 * @param sharedwith (mandatory, NON-NULL) The sharedwith atsign, atsign you are going to share it with, e.g. "@bob"
 * @return int 0 on success, otherwise error (most likely malloc error)
 */
int atclient_atkey_set_sharedwith(atclient_atkey *atkey, const char *sharedwith);

/**
 * @brief Frees the memory allocated for the key in the atkey struct. This is already called by atclient_atkey_free and
 * should only be used for advanced pruposes, if you want to free the key before the end of life of your struct
 *
 * @param atkey the atkey struct that holds the allocated atkey->key memory
 */
void atclient_atkey_unset_key(atclient_atkey *atkey);

/**
 * @brief Frees the memory allocated for the namespacestr in the atkey struct. This is already called by
 * atclient_atkey_free and should only be used for advanced pruposes, if you want to free the namespacestr before the
 * end of life of your struct
 *
 * @param atkey the atkey struct that holds the allocated atkey->namespacestr memory
 */
void atclient_atkey_unset_namespacestr(atclient_atkey *atkey);

/**
 * @brief Free the memory allocated for the sharedby in the atkey struct. This is already called by atclient_atkey_free
 * and should only be used for advanced pruposes, if you want to free the sharedby before the end of life of your struct
 *
 * @param atkey the atkey struct that holds the allocated atkey->sharedby memory
 */
void atclient_atkey_unset_sharedby(atclient_atkey *atkey);

/**
 * @brief Frees the memory allocated for the sharedwith in the atkey struct. This is already called by
 * atclient_atkey_free and should only be used for advanced pruposes, if you want to free the sharedwith before the end
 * of life of your struct
 *
 * @param atkey the atkey struct that holds the allocated atkey->sharedwith memory
 */
void atclient_atkey_unset_sharedwith(atclient_atkey *atkey);

/**
 * @brief Evaluates the type of the atkey struct
 *
 * @param atkey the atkey struct to evaluate
 * @return atclient_atkey_type the type of the atkey struct, returns ATCLIENT_ATKEY_TYPE_UNKNOWN if an error occurred
 */
atclient_atkey_type atclient_atkey_get_type(const atclient_atkey *atkey);

/**
 * @brief Populate an atkey struct representing a PublicKey AtKey with null terminated strings. An example of a Public
 * AtKey would be 'public:name.namespace@alice'. Public AtKeys typically hold unencrypted values and can be seen by
 * unauthenticated atsigns. Be sure to call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate, assumed that this was already initialized via atclient_atkey_init
 * @param name the name of the atkey, e.g.: "name"
 * @param sharedby the sharedby (creator/pkam authenticated atsign) of the atkey, e.g.: "@alice"
 * @param namespacestr the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success
 */
int atclient_atkey_create_publickey(atclient_atkey *atkey, const char *name, const char *sharedby, const char *namespacestr);

/**
 * @brief Populate an atkey struct representing a SelfKey AtKey with null terminated strings. An example of a SelfKey
 * AtKey would be 'name.namespace@alice'. SelfKeys can only be accessible by the sharedby (creator) atsign. Be sure to
 * call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate, assumed that this was already initialized via atclient_atkey_init
 * @param name the name of the atkey, e.g.: "name"
 * @param sharedby the sharedby (creator/pkam authenticated atsign) of the atkey, e.g.: "@alice"
 * @param namespacestr the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success
 */
int atclient_atkey_create_selfkey(atclient_atkey *atkey, const char *name, const char *sharedby, const char *namespacestr);

/**
 * @brief Populate an atkey struct representing a SharedKey AtKey given null terminated strings. An example of a
 * SharedKey AtKey would be '@sharedwith:name.namesapce@sharedby'. SharedKeys can only be accessible by the sharedwith
 * and sharedby atsigns, as they are encrypted with a shared AES key which is encrypted with the each of their RSA keys.
 * Be sure to call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate, assumed that this was already initialized via atclient_atkey_init
 * @param name name of your key, e.g. "name"
 * @param sharedby the shared by atsign, e.g. "@alice"
 * @param sharedwith the sharedwith atsign, atsign you are going to share it with, e.g. "@bob"
 * @param namespacestr the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success
 */
int atclient_atkey_create_sharedkey(atclient_atkey *atkey, const char *name, const char *sharedby,
                                    const char *sharedwith, const char *namespacestr);

#endif
