#ifndef ATCLIENT_ATKEY_H
#define ATCLIENT_ATKEY_H

#include "atclient/metadata.h"
#include <stddef.h>
#include <stdint.h>

#define ATCLIENT_ATKEY_KEY_LEN 55                                                                // 55 utf7 chars
#define ATCLIENT_ATKEY_NAMESPACE_LEN 55                                                          // 55 utf7 chars
#define ATCLIENT_ATKEY_COMPOSITE_LEN (ATCLIENT_ATKEY_KEY_LEN + 1 + ATCLIENT_ATKEY_NAMESPACE_LEN) // {key}.{namespace}
#define ATCLIENT_ATKEY_FULL_LEN                                                                                        \
  (ATCLIENT_ATSIGN_FULL_LEN + 1 + ATCLIENT_ATKEY_COMPOSITE_LEN +                                                       \
   ATCLIENT_ATSIGN_FULL_LEN) // {full_atsign}:{composite_key}{full_atsign}

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_ATKEY_KEY_INDEX 0
#define ATCLIENT_ATKEY_NAMESPACE_STR_INDEX 0
#define ATCLIENT_ATKEY_SHARED_BY_INDEX 0
#define ATCLIENT_ATKEY_SHARED_WITH_INDEX 0

#define ATCLIENT_ATKEY_KEY_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_ATKEY_NAMESPACE_STR_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_ATKEY_SHARED_BY_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_ATKEY_SHARED_WITH_INITIALIZED (VALUE_INITIALIZED << 3)

typedef enum atclient_atkey_type {
  ATCLIENT_ATKEY_TYPE_UNKNOWN = 0,
  ATCLIENT_ATKEY_TYPE_PUBLIC_KEY,
  ATCLIENT_ATKEY_TYPE_SELF_KEY,
  ATCLIENT_ATKEY_TYPE_SHARED_KEY,
} atclient_atkey_type;

typedef struct atclient_atkey {
  char *key;
  char *namespace_str;
  char *shared_by;
  char *shared_with;

  uint8_t _initialized_fields[1]; // internal field to track which fields are allocated

  atclient_atkey_metadata metadata;

} atclient_atkey;

/**
 * @brief Initialize an atkey struct. This function should be called before any other atkey functions.
 *
 * @param atkey the atkey struct to initialize
 */
void atclient_atkey_init(atclient_atkey *atkey);

/**
 * @brief Clones an atkey struct. The function will allocate new memory on everything
 * 
 * @param dst the atkey struct to clone to, assumed to be already initialized via atclient_atkey_init
 * @param src the atkey struct to clone from, assumed to be already initialized via atclient_atkey_init
 * @return int 0 on success
 */
int atclient_atkey_clone(atclient_atkey *dst, const atclient_atkey *src);

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
 * @brief Returns true if atkey->namespace_str is initialized and allocated, and the value is safe for reading
 *
 * @param atkey the atkey struct to read
 * @return true, if the namespace_str is initialized and allocated and is safe for reading
 * @return false, if the namespace_str is not initialized and not allocated and is not safe for reading, high chance that
 * it holds garbage
 */
bool atclient_atkey_is_namespacestr_initialized(const atclient_atkey *atkey);

/**
 * @brief Returns true if atkey->shared_by is initialized and allocated, and the value is safe for reading
 *
 * @param atkey the atkey struct to read
 * @return true, if the shared_by is initialized and allocated and is safe for reading
 * @return false, if the shared_by is not initialized and not allocated and is not safe for reading, high chance that it
 * holds garbage
 */
bool atclient_atkey_is_shared_by_initialized(const atclient_atkey *atkey);

/**
 * @brief Returns true if atkey->shared_with is initialized and allocated, and the value is safe for reading
 *
 * @param atkey the atkey struct to read
 * @return true, if the shared_with is initialized and allocated and is safe for reading
 * @return false, if the shared_with is not initialized and not allocated and is not safe for reading, high chance that
 * it holds garbage 🤠
 */
bool atclient_atkey_is_shared_with_initialized(const atclient_atkey *atkey);

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
 * @brief Dynamically allocates memory and duplicates namespace_str to be stored in the atkey struct. If this is
 * allocated, then it is freed with atclient_atkey_free by the end of life of your struct
 *
 * @param atkey (mandatory, NON-NULL) The atkey struct to populate, assumed that this was already initialized via
 * atclient_atkey_init
 * @param namespace_str (mandatory, NON-NULL) The namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success, otherwise error (most likely malloc error)
 */
int atclient_atkey_set_namespace_str(atclient_atkey *atkey, const char *namespace_str);

/**
 * @brief Dynamically allocates memory and duplicates shared_by to be stored in the atkey struct. If this is allocated,
 * then it is freed with atclient_atkey_free by the end of life of your struct
 *
 * @param atkey (mandatory, NON-NULL) The atkey struct to populate, assumed that this was already initialized via
 * atclient_atkey_init
 * @param shared_by (mandatory, NON-NULL) The shared_by (creator/pkam authenticated atsign) of the atkey, e.g.: "@alice"
 * @return int 0 on success, otherwise error (most likely malloc error)
 */
int atclient_atkey_set_shared_by(atclient_atkey *atkey, const char *shared_by);

/**
 * @brief Dynamically allocates memory and duplicates shared_with to be stored in the atkey struct. If this is allocated,
 * then it is freed with atclient_atkey_free by the end of life of your struct
 *
 * @param atkey  (mandatory, NON-NULL) The atkey struct to populate, assumed that this was already initialized via
 * atclient_atkey_init
 * @param shared_with (mandatory, NON-NULL) The shared_with atsign, atsign you are going to share it with, e.g. "@bob"
 * @return int 0 on success, otherwise error (most likely malloc error)
 */
int atclient_atkey_set_shared_with(atclient_atkey *atkey, const char *shared_with);

/**
 * @brief Frees the memory allocated for the key in the atkey struct. This is already called by atclient_atkey_free and
 * should only be used for advanced pruposes, if you want to free the key before the end of life of your struct
 *
 * @param atkey the atkey struct that holds the allocated atkey->key memory
 */
void atclient_atkey_unset_key(atclient_atkey *atkey);

/**
 * @brief Frees the memory allocated for the namespace_str in the atkey struct. This is already called by
 * atclient_atkey_free and should only be used for advanced pruposes, if you want to free the namespace_str before the
 * end of life of your struct
 *
 * @param atkey the atkey struct that holds the allocated atkey->namespace_str memory
 */
void atclient_atkey_unset_namespace_str(atclient_atkey *atkey);

/**
 * @brief Free the memory allocated for the shared_by in the atkey struct. This is already called by atclient_atkey_free
 * and should only be used for advanced pruposes, if you want to free the shared_by before the end of life of your struct
 *
 * @param atkey the atkey struct that holds the allocated atkey->shared_by memory
 */
void atclient_atkey_unset_shared_by(atclient_atkey *atkey);

/**
 * @brief Frees the memory allocated for the shared_with in the atkey struct. This is already called by
 * atclient_atkey_free and should only be used for advanced pruposes, if you want to free the shared_with before the end
 * of life of your struct
 *
 * @param atkey the atkey struct that holds the allocated atkey->shared_with memory
 */
void atclient_atkey_unset_shared_with(atclient_atkey *atkey);

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
 * @param shared_by the shared_by (creator/pkam authenticated atsign) of the atkey, e.g.: "@alice"
 * @param namespace_str the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success
 */
int atclient_atkey_create_public_key(atclient_atkey *atkey, const char *name, const char *shared_by, const char *namespace_str);

/**
 * @brief Populate an atkey struct representing a SelfKey AtKey with null terminated strings. An example of a SelfKey
 * AtKey would be 'name.namespace@alice'. SelfKeys can only be accessible by the shared_by (creator) atsign. Be sure to
 * call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate, assumed that this was already initialized via atclient_atkey_init
 * @param name the name of the atkey, e.g.: "name"
 * @param shared_by the shared_by (creator/pkam authenticated atsign) of the atkey, e.g.: "@alice"
 * @param namespace_str the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success
 */
int atclient_atkey_create_self_key(atclient_atkey *atkey, const char *name, const char *shared_by, const char *namespace_str);

/**
 * @brief Populate an atkey struct representing a SharedKey AtKey given null terminated strings. An example of a
 * SharedKey AtKey would be '@shared_with:name.namesapce@shared_by'. SharedKeys can only be accessible by the shared_with
 * and shared_by atsigns, as they are encrypted with a shared AES key which is encrypted with the each of their RSA keys.
 * Be sure to call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate, assumed that this was already initialized via atclient_atkey_init
 * @param name name of your key, e.g. "name"
 * @param shared_by the shared by atsign, e.g. "@alice"
 * @param shared_with the shared_with atsign, atsign you are going to share it with, e.g. "@bob"
 * @param namespace_str the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success
 */
int atclient_atkey_create_shared_key(atclient_atkey *atkey, const char *name, const char *shared_by,
                                    const char *shared_with, const char *namespace_str);

#endif
