#ifndef ATCLIENT_ATKEY_H
#define ATCLIENT_ATKEY_H

#include "atclient/atstr.h"
#include "atclient/metadata.h"
#include <stddef.h>

typedef enum atclient_atkey_type {
  ATCLIENT_ATKEY_TYPE_UNKNOWN = 0,
  ATCLIENT_ATKEY_TYPE_PUBLICKEY,
  ATCLIENT_ATKEY_TYPE_SELFKEY,
  ATCLIENT_ATKEY_TYPE_SHAREDKEY,
} atclient_atkey_type;

typedef struct atclient_atkey {
  // TODO: remove atkey_type and replace it with a policy function that infers atkeytype given atclient_atkey & atclient
  atclient_atkey_type atkeytype;

  // TODO: this should be called atkey.key to be consistent with dart
  atclient_atstr name;
  atclient_atstr namespacestr;
  atclient_atstr sharedby;
  atclient_atstr sharedwith;

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
 * @brief populate an atkey struct given a null terminated string. Be sure to call the atclient_atkey_init function
 * before calling this function.
 *
 * @param atkey the atkey struct to populate, assumed that this was already initialized via atclient_atkey_init
 * @param atkeystr the atkeystr to derive from (e.g. 'public:name.wavi@alice')
 * @param atkeylen the length of the atkeystr
 * @return int 0 on success, that a struct was able to be created from the string. (the string followed proper key
 * nomenclature)
 */
int atclient_atkey_from_string(atclient_atkey *atkey, const char *atkeystr, const size_t atkeylen);

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
 * @brief convert an atkey struct to its string format
 *
 * @param atkey atkey struct to read, assumed that this was already initialized via atclient_atkey_init
 * @param atkeystr buffer to write to, assumed that this was already allocated
 * @param atkeystrsize buffer allocated size
 * @param atkeystrlen the written (output) length of the atkeystr
 * @return int 0 on success
 */
int atclient_atkey_to_string(const atclient_atkey *atkey, char *atkeystr, const size_t atkeystrsize,
                             size_t *atkeystrlen);

/**
 * @brief Populate an atkey struct representing a PublicKey AtKey with null terminated strings. An example of a Public
 * AtKey would be 'public:name.namespace@alice'. Public AtKeys typically hold unencrypted values and can be seen by
 * unauthenticated atsigns. Be sure to call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate, assumed that this was already initialized via atclient_atkey_init
 * @param name the name of the atkey, e.g.: "name"
 * @param namelen the length of the name (use strlen in most cases)
 * @param sharedby the sharedby (creator/pkam authenticated atsign) of the atkey, e.g.: "@alice"
 * @param sharedbylen the length of the sharedby (use strlen in most cases)
 * @param namespacestr the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @param namespacestrlen the length of the namespacestr (use strlen in most cases)
 * @return int 0 on success
 */
int atclient_atkey_create_publickey(atclient_atkey *atkey, const char *name, const size_t namelen, const char *sharedby,
                                    const size_t sharedbylen, const char *namespacestr, const size_t namespacestrlen);

/**
 * @brief Populate an atkey struct representing a SelfKey AtKey with null terminated strings. An example of a SelfKey
 * AtKey would be 'name.namespace@alice'. SelfKeys can only be accessible by the sharedby (creator) atsign. Be sure to
 * call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate, assumed that this was already initialized via atclient_atkey_init
 * @param name the name of the atkey, e.g.: "name"
 * @param namelen the length of the name (use strlen in most cases)
 * @param sharedby the sharedby (creator/pkam authenticated atsign) of the atkey, e.g.: "@alice"
 * @param sharedbylen the length of the sharedby (use strlen in most cases)
 * @param namespacestr the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @param namespacestrlen the length of the namespacestr (use strlen in most cases)
 * @return int 0 on success
 */
int atclient_atkey_create_selfkey(atclient_atkey *atkey, const char *name, const size_t namelen, const char *sharedby,
                                  const size_t sharedbylen, const char *namespacestr, const size_t namespacestrlen);

/**
 * @brief Populate an atkey struct representing a SharedKey AtKey given null terminated strings. An example of a
 * SharedKey AtKey would be '@sharedwith:name.namesapce@sharedby'. SharedKeys can only be accessible by the sharedwith
 * and sharedby atsigns, as they are encrypted with a shared AES key which is encrypted with the each of their RSA keys.
 * Be sure to call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate, assumed that this was already initialized via atclient_atkey_init
 * @param name name of your key, e.g. "name"
 * @param namelen the length of the name (use strlen in most cases)
 * @param sharedby the shared by atsign, e.g. "@alice"
 * @param sharedbylen the length of the sharedby (use strlen in most cases)
 * @param sharedwith the sharedwith atsign, atsign you are going to share it with, e.g. "@bob"
 * @param sharedwithlen the length of the sharedwith (use strlen in most cases)
 * @param namespacestr the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @param namespacestrlen the length of the namespacestr (use strlen in most cases)
 * @return int 0 on success
 */
int atclient_atkey_create_sharedkey(atclient_atkey *atkey, const char *name, const size_t namelen, const char *sharedby,
                                    const size_t sharedbylen, const char *sharedwith, const size_t sharedwithlen,
                                    const char *namespacestr, const size_t namespacestrlen);

#endif
