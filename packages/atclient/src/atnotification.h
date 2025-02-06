#ifndef ATCLIENT_SRC_ATNOTIFICATION_H
#define ATCLIENT_SRC_ATNOTIFICATION_H
#ifdef __cplusplus
extern "C" {
#endif

#include "atclient/atnotification.h"

void atclient_atnotification_id_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_from_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_to_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_key_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_value_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_operation_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_epoch_millis_set_initialized(atclient_atnotification *notification,
                                                          const bool initialized);
void atclient_atnotification_message_type_set_initialized(atclient_atnotification *notification,
                                                          const bool initialized);
void atclient_atnotification_is_encrypted_set_initialized(atclient_atnotification *notification,
                                                          const bool initialized);
void atclient_atnotification_enc_key_name_set_initialized(atclient_atnotification *notification,
                                                          const bool initialized);
void atclient_atnotification_enc_algo_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_iv_nonce_set_initialized(atclient_atnotification *notification, const bool initialized);
void atclient_atnotification_ske_enc_key_name_set_initialized(atclient_atnotification *notification,
                                                              const bool initialized);
void atclient_atnotification_ske_enc_algo_set_initialized(atclient_atnotification *notification,
                                                          const bool initialized);
void atclient_atnotification_decrypted_value_set_initialized(atclient_atnotification *notification,
                                                             const bool initialized);
#ifdef __cplusplus
}
#endif
#endif
