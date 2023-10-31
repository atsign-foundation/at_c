#ifndef ATKEY_H
#define ATKEY_H

#include "atclient/atsign.h"
#include "atclient/metadata.h"

typedef enum atclient_atkey_type
{
	UNKNOWN = 0,
	PUBLICKEY,
	SELFKEY,
	SHAREDKEY,
} atclient_atkey_type;

typedef struct atclient_atkey
{
	unsigned long namelen;
	char *namestr;
	unsigned long nameolen;

	unsigned long namespacelen;
	char *namespacestr;
	unsigned long namespaceolen;

	unsigned long sharedwithlen;
	char *sharedwithstr;
	unsigned long sharedwitholen;

	unsigned long sharedbylen;
	char *sharedbystr;
	unsigned long sharedbyolen;

	atclient_atkey_type atkeytype;

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
 * @brief populate an atkey struct given a null terminated string. Be sure to call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate
 * @param atkeystr the atkeystr to derive from (e.g. 'public:name.wavi@alice')
 * @return int 0 on success, that a struct was able to be created from the string. (the string followed proper key nomenclature)
 */
int atclient_atkey_create_from_string(atclient_atkey *atkey, const char *atkeystr);

/**
 * @brief convert an atkey struct to its string format
 *
 * @param atkey atkey struct to read
 * @param atkeystr buffer to write to
 * @param atkeystrlen buffer allocated size
 * @param atkeystrolen the written (output) length of the atkeystr
 * @return int 0 on success
 */
int atclient_atkey_to_string(atclient_atkey atkey, char *atkeystr, unsigned long *atkeystrlen, unsigned long atkeystrolen);

/**
 * @brief Populate an atkey struct representing a PublicKey AtKey with null terminated strings. An example of a Public AtKey would be 'public:name.namespace@alice'. Public AtKeys typically hold unencrypted values and can be seen by unauthenticated atsigns. Be sure to call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate
 * @param name the name of the atkey, e.g.: "name"
 * @param sharedby the sharedby (creator/pkam authenticated atsign) of the atkey, e.g.: "@alice"
 * @param namespacestr the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success
 */
int atclient_atkey_create_publickey(atclient_atkey *atkey, const char *name, const atclient_atsign sharedby, const char *namespacestr);

/**
 * @brief Populate an atkey struct representing a SelfKey AtKey with null terminated strings. An example of a SelfKey AtKey would be 'name.namespace@alice'. SelfKeys can only be accessible by the sharedby (creator) atsign. Be sure to call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate
 * @param name the name of the atkey, e.g.: "name"
 * @param sharedby the sharedby (creator/pkam authenticated atsign) of the atkey, e.g.: "@alice"
 * @param namespacestr the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success
 */
int atclient_atkey_create_selfkey(atclient_atkey *atkey, char *name, const atclient_atsign sharedby, char *namespacestr);

/**
 * @brief Populate an atkey struct representing a SharedKey AtKey given null terminated strings. An example of a SharedKey AtKey would be '@sharedwith:name.namesapce@sharedby'. SharedKeys can only be accessible by the sharedwith and sharedby atsigns, as they are encrypted with a shared AES key which is encrypted with the each of their RSA keys. Be sure to call the atclient_atkey_init function before calling this function.
 *
 * @param atkey the atkey struct to populate
 * @param name name of your key, e.g. "name"
 * @param sharedby the shared by atsign, e.g. "@alice"
 * @param sharedwith the sharedwith atsign, atsign you are going to share it with, e.g. "@bob"
 * @param namespacestr the namespace of your application, e.g. "banking_app" (NULLABLE)
 * @return int 0 on success
 */
int atclient_atkey_create_sharedkey(atclient_atkey *atkey, char *name, const atclient_atsign sharedby, const atclient_atsign sharedwith, char *namespacestr);

#endif