#include "atclient/notify.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "atclient/encryption_key_helpers.h"
#include "atclient/stringutils.h"
#include <atchops/aes.h>
#include <atchops/aesctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atchops/uuid.h>
#include <atlogger/atlogger.h>
#include <mbedtls/threading.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define TAG "atclient_notify"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static int generate_cmd(const atclient_notify_params *params, const char *cmdvalue, const size_t cmdvaluelen,
                        char **ocmd, size_t *ocmdolen);
static size_t calculate_cmd_size(const atclient_notify_params *params, const size_t cmdvaluelen, size_t *atkeyolen,
                                 size_t *medatastrolen);

int atclient_notify(atclient *ctx, atclient_notify_params *params, char **notification_id) {
  int ret = 1;

  if (ctx->async_read) {
    atlogger_log(
        TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
        "atclient_notify cannot be called from an async_read=true atclient, it will cause a race condition.\n");
    return ret;
  }

  // holds the value to be added to the cmd, could be plaintext or ciphertext
  char *cmdvalue = NULL;
  size_t cmdvaluelen = 0;

  // holds end notify: command
  char *cmd = NULL;
  size_t cmdsize = 0;

  // Step 1 encrypt the value if needed
  if (params->value != NULL && params->should_encrypt) {
    const size_t ciphertextsize =
        (size_t)(((strlen(params->value) * 2) + 15) / 16) * 16; // round up to the next multiple of 16
    unsigned char ciphertext[ciphertextsize];
    memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
    size_t ciphertextlen = 0;

    const size_t ciphertextbase64size = atchops_base64_encoded_size(ciphertextsize) + 1;
    unsigned char ciphertextbase64[ciphertextbase64size];
    memset(ciphertextbase64, 0, sizeof(unsigned char) * ciphertextbase64size);
    size_t ciphertextbase64len = 0;

    const size_t ivbase64size = atchops_base64_encoded_size(ATCHOPS_IV_BUFFER_SIZE) + 1;
    unsigned char ivbase64[ivbase64size];
    memset(ivbase64, 0, sizeof(unsigned char) * ivbase64size);
    size_t ivbase64len = 0;

    const size_t sharedenckeysize = ATCHOPS_AES_256 / 8;
    unsigned char sharedenckey[sharedenckeysize];
    memset(sharedenckey, 0, sizeof(unsigned char) * sharedenckeysize);
    size_t sharedenckeylen;

    if (params->shared_encryption_key == NULL) {
      char *recipient_atsign_with_at = NULL;
      if ((ret = atclient_stringutils_atsign_with_at(params->atkey->shared_with, &recipient_atsign_with_at)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_stringutils_atsign_with_at failed with code %d\n",
                     ret);
        return ret;
      }
      if ((ret = atclient_get_shared_encryption_key_shared_by_me(ctx, recipient_atsign_with_at, sharedenckey)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "atclient_get_shared_encryption_key_shared_by_me: %d\n", ret);
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Creating shared encryption key\n");
        if ((ret = atclient_create_shared_encryption_key_pair_for_me_and_other(ctx, recipient_atsign_with_at,
                                                                               sharedenckey)) != 0) {
          atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                       "atclient_create_shared_encryption_key_pair_for_me_and_other: %d\n", ret);
          free(recipient_atsign_with_at);
          return ret;
        }
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Created shared encryption key successfully\n");
      }
      free(recipient_atsign_with_at);
    }

    unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
    ret = atchops_iv_generate(iv);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_iv_generate failed with code %d\n", ret);
      return ret;
    }

    ret = atchops_base64_encode(iv, ATCHOPS_IV_BUFFER_SIZE, ivbase64, ivbase64size, &ivbase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode failed with code %d\n", ret);
      return ret;
    }

    ret = atclient_atkey_metadata_set_iv_nonce(&(params->atkey->metadata), (char *)ivbase64);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_iv_nonce failed with code %d\n", ret);
      return ret;
    }

    ret = atchops_aesctr_encrypt(sharedenckey, ATCHOPS_AES_256, iv, (unsigned char *)params->value,
                                 strlen(params->value), ciphertext, ciphertextsize, &ciphertextlen);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt failed with code %d\n", ret);
      return ret;
    }

    ret =
        atchops_base64_encode(ciphertext, ciphertextlen, ciphertextbase64, ciphertextbase64size, &ciphertextbase64len);
    if (ret != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode failed with code %d\n", ret);
      return ret;
    }

    cmdvalue = malloc(sizeof(char) * (ciphertextbase64len + 1));
    memcpy(cmdvalue, ciphertextbase64, ciphertextbase64len);
    cmdvalue[ciphertextbase64len] = '\0';
    cmdvaluelen = ciphertextbase64len;
  } else if (params->value != NULL && !params->should_encrypt) {
    cmdvaluelen = strlen(params->value);
    cmdvalue = malloc(sizeof(char) * (cmdvaluelen + 1));
    memcpy(cmdvalue, params->value, cmdvaluelen);
    cmdvalue[cmdvaluelen] = '\0';
  }

  size_t cmdlen = 0;

  ret = generate_cmd(params, cmdvalue, cmdvaluelen, &cmd, &cmdlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "generate_cmd failed with code %d\n", ret);
    goto exit;
  }

  // Step 6 send the encrypted notification
  const size_t recvsize = 64;
  unsigned char *recv = NULL;
  if (!ctx->async_read) {
    recv = malloc(sizeof(unsigned char) * recvsize);
    memset(recv, 0, sizeof(unsigned char) * recvsize);
  }
  size_t recvlen = 0;

  ret = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)cmd, cmdlen, recv, recvsize, &recvlen);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send failed with code %d\n", ret);
    goto exit;
  } else if (ctx->async_read) {
    goto exit;
  }
  // if starts with data:
  if (atclient_stringutils_starts_with((char *)recv, "data:")) {
    if (notification_id != NULL) { // if not null, then they care about the notification id
      // parse the notification id
      char *data = (char *)recv + strlen("data:");
      size_t datalen = recvlen - strlen("data:");
      if (datalen > 36) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Notification id too long\n");
        return 1;
      }
      *notification_id = malloc(sizeof(char) * (datalen + 1));
      if (*notification_id == NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
        return 1;
      }
      memcpy(*notification_id, data, datalen);
      (*notification_id)[datalen] = '\0';
    }
    ret = 0;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unexpected response: %.*s\n", (int)recvlen, recv);
    ret = 1;
  }

exit: {
  if (!ctx->async_read) {
    free(recv);
  }
  free(cmdvalue);
  free(cmd);
  return ret;
}
}

static size_t calculate_cmd_size(const atclient_notify_params *params, const size_t cmdvaluelen, size_t *atkeyolen,
                                 size_t *medatastrolen) {
  // notify command will look something like this:
  // "notify[:message_type:<type>][:priority:<priority>][:strategy:<strategy>][:ttln:<ttln>]<:atkey_metadata>:<atkey>[:<value>]\r\n"
  size_t cmdsize = 0;

  cmdsize += strlen("notify");

  if (atclient_notify_params_is_id_initialized(params) && strlen(params->id) > 0) {
    cmdsize += strlen(":id:") + strlen(params->id); // ":id:" + 36 char uuid
  }

  if (atclient_notify_params_is_operation_initialized(params) && params->operation != ATCLIENT_NOTIFY_OPERATION_NONE) {
    cmdsize += strlen(":") + strlen(atclient_notify_operation_str[params->operation]); // ":update" | ":delete"
  }

  if (atclient_notify_params_is_message_type_initialized(params) &&
      params->message_type != ATCLIENT_NOTIFY_MESSAGE_TYPE_NONE) {
    cmdsize += strlen(":message_type:") +
               strlen(atclient_notify_message_type_str[params->message_type]); // ":message_type" + ":text" | ":key"
  }

  if (atclient_notify_params_is_priority_initialized(params) && params->priority != ATCLIENT_NOTIFY_PRIORITY_NONE) {
    cmdsize += strlen(":priority:") +
               strlen(atclient_notify_priority_str[params->priority]); // ":priority" + ":low" | ":medium" | ":high"
  }

  if (atclient_notify_params_is_strategy_initialized(params) && params->strategy != ATCLIENT_NOTIFY_STRATEGY_NONE) {
    cmdsize += strlen(":strategy:") +
               strlen(atclient_notify_strategy_str[params->strategy]); // ":strategy" + ":all" | ":latest"
  }

  if (atclient_notify_params_is_notification_expiry_initialized(params) && params->notification_expiry > 0) {
    cmdsize += strlen(":ttln:") + atclient_stringutils_long_strlen(params->notification_expiry); // :$ttln
  }

  if (atclient_notify_params_is_atkey_initialized(params)) {

    const size_t metadatastrlen = atclient_atkey_metadata_protocol_strlen(&params->atkey->metadata);
    cmdsize += strlen(":") + metadatastrlen; // :$metadata

    const size_t atkeylen = atclient_atkey_strlen(params->atkey);
    cmdsize += strlen(":") + atkeylen; // :$atkey

    if (cmdvaluelen > 0) {
      cmdsize += strlen(":") + cmdvaluelen; // :$value
    }
    *atkeyolen = atkeylen;
    *medatastrolen = metadatastrlen;
  }

  cmdsize += strlen("\r\n");

  cmdsize += 1; // null terminator


  return cmdsize;
}

static int generate_cmd(const atclient_notify_params *params, const char *cmdvalue, const size_t cmdvaluelen,
                        char **ocmd, size_t *ocmdolen) {
  int res = 1;

  char *cmd = NULL;
  char *metadata_protocol_str = NULL;

  char *atkeystr = NULL;

  size_t atkeylen = 0;
  size_t metadatastrlen = 0;

  size_t cmdsize = 0;

  cmdsize = calculate_cmd_size(params, cmdvaluelen, &atkeylen, &metadatastrlen);
  if (cmdsize <= 0) {
    res = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "calculate_cmd_size failed with code %d\n", cmdsize);
    goto exit;
  }

  // Step 3 allocate the buffer
  cmd = malloc(sizeof(char) * cmdsize);
  if (cmd == NULL) {
    res = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    goto exit;
  }
  memset(cmd, 0, sizeof(char) * cmdsize);

  // Step 4 build the command

  size_t off = 0;

  snprintf(cmd + off, cmdsize - off, "notify");
  off += strlen("notify");

  if (atclient_notify_params_is_id_initialized(params) && strlen(params->id) > 0) {
    snprintf(cmd + off, cmdsize - off, ":id:%s", params->id);
    off += strlen(":id:") + strlen(params->id);
  }

  if (atclient_notify_params_is_operation_initialized(params) && params->operation != ATCLIENT_NOTIFY_OPERATION_NONE) {
    snprintf(cmd + off, cmdsize - off, ":%s", atclient_notify_operation_str[params->operation]);
    off += strlen(":") + strlen(atclient_notify_operation_str[params->operation]);
  }

  if (atclient_notify_params_is_message_type_initialized(params) && params->message_type != ATCLIENT_NOTIFY_MESSAGE_TYPE_NONE) {
    snprintf(cmd + off, cmdsize - off, ":message_type:%s", atclient_notify_message_type_str[params->message_type]);
    off += strlen(":message_type:") + strlen(atclient_notify_message_type_str[params->message_type]);
  }

  if (atclient_notify_params_is_priority_initialized(params) && params->priority != ATCLIENT_NOTIFY_PRIORITY_NONE) {
    snprintf(cmd + off, cmdsize - off, ":priority:%s", atclient_notify_priority_str[params->priority]);
    off += strlen(":priority:") + strlen(atclient_notify_priority_str[params->priority]);
  }

  if (atclient_notify_params_is_strategy_initialized(params) && params->strategy != ATCLIENT_NOTIFY_STRATEGY_NONE) {
    snprintf(cmd + off, cmdsize - off, ":strategy:%s", atclient_notify_strategy_str[params->strategy]);
    off += strlen(":strategy:") + strlen(atclient_notify_strategy_str[params->strategy]);
  }

  if (atclient_notify_params_is_notification_expiry_initialized(params) && params->notification_expiry > 0) {
    snprintf(cmd + off, cmdsize - off, ":ttln:%lu", params->notification_expiry);
    off += strlen(":ttln:") + atclient_stringutils_long_strlen(params->notification_expiry);
  }

  if ((res = atclient_atkey_metadata_to_protocol_str(&(params->atkey->metadata), &metadata_protocol_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocol_str failed with code: %d\n",
                 res);
    goto exit;
  }
  snprintf(cmd + off, cmdsize - off, "%s", metadata_protocol_str);

  if (strlen(metadata_protocol_str) != metadatastrlen) {
    res = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_atkey_metadata_to_protocol_str mismatch. Expected %lu but got %lu\n", metadatastrlen,
                 strlen(metadata_protocol_str));
    goto exit;
  }
  off += strlen(metadata_protocol_str);

  if ((res = atclient_atkey_to_string(params->atkey, &atkeystr)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed with code: %d\n", res);
    return res;
  }
  const size_t atkeystrlen = strlen(atkeystr);
  if (atkeylen != atkeystrlen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string mismatch. Expected %lu but got %lu\n",
                 atkeylen, atkeystrlen);
    goto exit;
  }
  snprintf(cmd + off, cmdsize - off, ":%s", atkeystr);
  off += strlen(":") + atkeylen;

  if (cmdvaluelen > 0) {
    snprintf(cmd + off, cmdsize - off, ":%.*s", (int)cmdvaluelen, cmdvalue);
    off += strlen(":") + cmdvaluelen;
  }

  snprintf(cmd + off, cmdsize - off, "\r\n");
  off += strlen("\r\n");

  // add null terminator
  cmd[off] = '\0';
  off += 1;

  // if cmdsize != off, then WARN that cmd size is not what was expected
  if (cmdsize != (off + 1)) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN, "cmdsize was %lu when it was expected to be %lu\n", cmdsize,
                 (off + 1));
  }

  *ocmd = cmd;
  *ocmdolen = off - 1; // off includes the null terminator

  res = 0;
  goto exit;

exit: {
  free(metadata_protocol_str);
  return res;
}
}
