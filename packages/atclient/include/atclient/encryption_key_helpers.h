#ifndef ATCLIENT_ENCRYPTION_KEY_HELPERS_H
#define ATCLIENT_ENCRYPTION_KEY_HELPERS_H

#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/atkeys.h"

/**
 * @brief Retreives the public encryption key of a given atsign.
 *
 * @param ctx Initialized atclient context. Assumed to be non-null, initialized with atclient_init, and pkam
 * authenticated using atclient_pkam_authenticate (required)
 * @param recipient the atsign of the recipient with @ symbol (required)
 * @param public_encryption_key The output rsa public key base64 encoded and non-encrypted (required). Essentially what
 * you get from doing a plookup. Mandatory field, non-null. The caller is responsible for freeing the memory. If the
 * return code is 0, then the memory is allocated and the caller is responsible for freeing it and is safe for reading
 * and usage.
 * @return int 0 on success, error otherwise
 */
int atclient_get_public_encryption_key(atclient *ctx, const char *atsign, char **public_encryption_key);

/**
 * @brief Looks up the symmetric shared key which the atclient's atsign shared with the recipient's atsign.
 * If no key is found and create_new_if_not_found is true, it will create, store and share a new one with the
 * recipient's atsign.
 *
 * @param ctx Initialized atclient context (required)
 * @param recipient atsign of the recipient with @ symbol (required)
 * @param shared_encryption_key_shared_by_me (required to receive output) the non-encrypted non-base64-encoded shared
 * encryption AES 256 key in raw bytes. Expected to be non-null and has 32 bytes of memory allocated to this address to
 * hold key.
 * @return int 0 on success, error otherwise
 */
int atclient_get_shared_encryption_key_shared_by_me(atclient *ctx, const char *recipient_atsign,
                                                    unsigned char *shared_encryption_key_shared_by_me);

/**
 * @brief Looks up the symmetric shared key which the recipient's atsign shared with atclient's atsign.
 * If no key is found, the function will return an error.
 *
 * @param ctx Initialized atclient context (required)
 * @param root_conn initialized root connection
 * @param recipient the atsign of the recipient with @ symbol (required)
 * @param shared_encryption_key_shared_by_other (required to receive output) the non-encrypted non-base64-encoded shared
 * encryption AES 256 key in raw bytes.. Expected to be non-null and has 32 bytes of memory allocated to this address to
 * hold key.
 * @return int 0 on success, error otherwise
 */
int atclient_get_shared_encryption_key_shared_by_other(atclient *ctx, const char *recipient,
                                                       unsigned char *shared_encryption_key_shared_by_other);

/**
 * @brief Creates a shared encryption key pair and puts it in your atServer. One is made for you to use for encrypting
 * data to send to other, and the other is for the recipient to use to decrypt the data that you sent
 * (shared_key.other@me and @other:shared_key@me)
 *
 * @param atclient non-null atclient context (must be initialized and pkam_authenticated)
 * @param sharedby non-null atSign (with @ symbol) and null-terminated. Example "@bob"
 * @param sharedwith non-null atSign (with @ symbol) and null-terminated. Example "@bob"
 * @param shared_encryption_key_shared_by_me_with_other holds the output shared encryption key that was created by this
 * function, to be shared with the recipient. Expected to be non-null and has 32 bytes of memory allocated to this
 * address to hold key. This key is not base64 encoded and not encrypted and is in raw bytes.
 * @return int 0 on success, error otherwise
 */
int atclient_create_shared_encryption_key_pair_for_me_and_other(
    atclient *atclient, const char *sharedby, const char *sharedwith,
    unsigned char *shared_encryption_key_shared_by_me_with_other);

#endif // ATCLIENT_ENCRYPTION_KEY_HELPERS_H
