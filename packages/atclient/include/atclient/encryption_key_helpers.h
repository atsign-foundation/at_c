#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/atkeys.h"
#include "atlogger/atlogger.h"

/**
 * @brief Looks up the symmetric shared key which the atclient's atsign shared with the recipient's atsign.
 * If no key is found and create_new_if_not_found is true, it will create, store and share a new one with the
 * recipient's atsign.
 *
 * @param ctx Initialized atclient context (required)
 * @param recipient An atclient_atsign struct corresponding to the atsign with whom the key was shared (required)
 * @param enc_key_shared_by_me The output shared key in b64 format (required)
 * @param create_new_if_not_found true if in case the symmetric shared key does not exist, you would like it to be
 * created / false if not (required)
 * @return int 0 on success, error otherwise
 */
int atclient_get_shared_encryption_key_shared_by_me(atclient *ctx, const atclient_atsign *recipient,
                                                    char *enc_key_shared_by_me, bool create_new_if_not_found);

/**
 * @brief Looks up the symmetric shared key which the recipient's atsign shared with atclient's atsign.
 * If no key is found, the function will return an error.
 *
 * @param ctx Initialized atclient context (required)
 * @param root_conn initialized root connection
 * @param recipient An atclient_atsign struct corresponding to the atsign who shared the key with the atclient’s atsign
 * (required)
 * @param enc_key_shared_by_other the output shared key in b64 format (required)
 * @return int 0 on success, error otherwise
 */
int atclient_get_shared_encryption_key_shared_by_other(atclient *ctx, const atclient_atsign *recipient,
                                                       char *enc_key_shared_by_other);

/**
 * @brief Retreives the public encryption key of a given atsign.
 *
 * @param ctx Initialized atclient context (required)
 * @param recipient An atclient_atsign struct corresponding to the atsign which public encryption key you would like to
 * obtain. It may receive a NULL value, in which case, the atclient_atsign contained in the ctx parameter will be used
 * (required)
 * @param public_encryption_key The output public key in b64 format (required)
 * @return int 0 on success, error otherwise
 */
int atclient_get_public_encryption_key(atclient *ctx, const atclient_atsign *atsign,
                                       char *public_encryption_key);

/**
 * @brief Creates a shared encryption key pair and puts it in your atServer. One is made for you to use for encrypting
 * data to send to other, and the other is for the recipient to use to decrypt the data that you sent
 * (shared_key.other@me and @other:shared_key@me)
 *
 * @param atclient the atclient context (must be initialized and pkam_authenticated)
 * @param sharedby
 * @param sharedwith
 * @param sharedenckeybyme
 * @return int
 */
int atclient_create_shared_encryption_key_pair_for_me_and_other(atclient *atclient, const atclient_atsign *sharedby,
                                                                const atclient_atsign *sharedwith,
                                                                char *sharedenckeybyme);
