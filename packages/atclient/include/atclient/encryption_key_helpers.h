#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/atkeys.h"
#include "atlogger/atlogger.h"

/**
 * @brief Looks up the symmetric shared key which the atclient's atsign shared with the recipient's atsign.
 * If no key is found and create_new_if_not_found is true, it will create, store and share a new one with the
 * sharedwith's atsign.
 *
 * @param ctx Initialized atclient context (required)
 * @param sharedwith the atsign with whom you would like to share the shared encryption key with (required) (e.g. \"@bob|")
 * @param sharedwithlen The length of the sharedwith atsign (required), most people use strlen(sharedwith)
 * @param sharedenckey The output shared key in raw bytes, ready to be used for encryption (required), always 32 bytes, assumed to be allocated by the caller with sufficient space (at least 32 bytes in size)
 * @return int 0 on success, error otherwise
 */
int atclient_get_shared_encryption_key_shared_by_me(atclient *ctx, const char *sharedwith, const size_t sharedwithlen,
                                                    unsigned char *sharedenckey) ;

/**
 * @brief Looks up the symmetric shared key which the recipient's atsign shared with atclient's atsign.
 * If no key is found, the function will return an error.
 *
 * @param ctx Initialized atclient context (required), assumed to be pkam_authenticated
 * @param sharedby the atsign who shared the key with you (required) (e.g. I am \"@alice\" and \"@bob|" is sharing the key with me, so sharedby is \"@bob|")
 * @param sharedbylen The length of the sharedby atsign (required), most people use strlen(sharedby)
 * @param sharedenckey the output shared key in raw bytes, ready to be used for encryption (required), always 32 bytes, assumed to be allocated by the caller with sufficient space (at least 32 bytes in size)
 * @return int 0 on success, error otherwise
 */
int atclient_get_shared_encryption_key_shared_by_other(atclient *ctx, const char *sharedby, const size_t sharedbylen,
                                                       unsigned char *sharedenckey);

/**
 * @brief Retreives the public encryption key of a given atsign.
 *
 * @param ctx Initialized atclient context (required), assumed to be pkam_authenticated
 * @param atsign the atsign whose public encryption key you want to retrieve (required) (e.g. \"@bob|"), assumed to be a null terminated string
 * @param atsignlen The length of the atsign (required), most people use strlen(atsign)
 * @param publicenckeybase64 The output public key in b64 format (required)
 * @param publicenckeybase64size The size of the output buffer (required)
 * @param publicenckeybase64len The length of the output public key, NULLABLE, if your buffer is initialized with zeroes, this is the same thing as doing strlen(publicenckeybase64)
 * @return int 0 on success, error otherwise
 */
int atclient_get_public_encryption_key(atclient *ctx, const char *atsign, const size_t atsignlen, char *publicenckeybase64, const size_t publicenckeybase64size, size_t *publicenckeybase64len);

/**
 * @brief Creates a shared encryption key pair and puts it in your atServer. One is made for you to use for encrypting
 * data to send to other, and the other is for the recipient to use to decrypt the data that you sent
 * (shared_key.other@me and @other:shared_key@me)
 *
 * @param atclient the atclient context (must be initialized and pkam_authenticated)
 * @param sharedwith the atsign with whom you would like to share the shared encryption key with
 * @param sharedwithlen the length of the sharedwith atsign, most people use strlen(sharedwith)
 * @param sharedenckey the output shared encryption key in raw bytes, ready to be used for encryption, always 32 bytes, assumed to be allocated by the caller with sufficient space (at least 32 bytes in size)
 * @return int 0 on success
 */
int atclient_create_shared_encryption_keypair_for_me_and_other(atclient *atclient, const char *sharedwith, const size_t sharedwithlen,
                                                                unsigned char *sharedenckey);
