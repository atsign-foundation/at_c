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

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static int generate_cmd(const atclient_notify_params *params, const char *cmdvalue, const size_t cmdvaluelen,
                        char **ocmd, size_t *ocmdolen);
static size_t calculate_cmd_size(const atclient_notify_params *params, const size_t cmdvaluelen, size_t *atkeyolen,
                                 size_t *medatastrolen);

#define TAG "atclient_notify"

void atclient_notify_params_init(atclient_notify_params *params) {
  memset(params, 0, sizeof(atclient_notify_params));
  memset(params->id, 0, sizeof(char) * 37); // uuid v4 + '\0'
  params->atkey = NULL;
  params->value = NULL;
  params->operation = ATCLIENT_NOTIFY_OPERATION_NONE;
  params->message_type = ATCLIENT_NOTIFY_MESSAGE_TYPE_KEY;
  params->priority = ATCLIENT_NOTIFY_PRIORITY_LOW;
  params->strategy = ATCLIENT_NOTIFY_STRATEGY_ALL;
  params->latest_n = 1;
  params->notifier = ATCLIENT_DEFAULT_NOTIFIER;
  params->notification_expiry = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
  params->shouldencrypt = true;
  params->sharedenckeybase64 = NULL;
}

void atclient_notify_params_create(atclient_notify_params *params, enum atclient_notify_operation operation,
                                   atclient_atkey *atkey, const char *value, bool shouldencrypt) {
  params->operation = operation;
  params->atkey = atkey;
  params->value = (char *)value;
  params->shouldencrypt = shouldencrypt;
}

void atclient_notify_params_free(atclient_notify_params *params) { memset(params, 0, sizeof(atclient_notify_params)); }

int atclient_notify(atclient *ctx, atclient_notify_params *params, char *notification_id) {

  int res = 1;

  if (ctx->async_read) {
    atlogger_log(
        TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
        "atclient_notify cannot be called from an async_read=true atclient, it will cause a race condition.\n");
    return res;
  }

  // holds the value to be added to the cmd, could be plaintext or ciphertext
  char *cmdvalue = NULL;
  size_t cmdvaluelen = 0;

  // holds end notify: command
  char *cmd = NULL;
  size_t cmdsize = 0;

  // Step 1 encrypt the value if needed
  if (params->value != NULL && params->shouldencrypt) {
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

    if (params->sharedenckeybase64 != NULL) {
      res = atchops_base64_decode((unsigned char *)params->sharedenckeybase64, strlen(params->sharedenckeybase64),
                                  sharedenckey, sharedenckeysize, &sharedenckeylen);
      if (res != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedenckeybase64 decode failed with code %d\n", res);
        return res;
      }
      if (sharedenckeylen != sharedenckeysize) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedenckeybase64 decode failed. Expected %lu but got %lu\n",
                     sharedenckeysize, sharedenckeylen);
        res = 1;
        return res;
      }
    } else {
      atclient_atsign recipient;
      const size_t sharedenckeybase64size = atchops_base64_encoded_size(sharedenckeysize) + 1;
      unsigned char sharedenckeybase64[sharedenckeybase64size];
      memset(sharedenckeybase64, 0, sizeof(unsigned char) * sharedenckeybase64size);
      if ((res = atclient_atsign_init(&recipient, params->atkey->sharedwith.str)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_init failed with code %d\n", res);
        return res;
      }
      if ((res = atclient_get_shared_encryption_key_shared_by_me(ctx, &recipient, (char *)sharedenckeybase64, true)) !=
          0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                     "atclient_get_shared_encryption_key_shared_by_me failed with code %d\n", res);
                     atclient_atsign_free(&recipient);
        return res;
      }
      if ((res = atchops_base64_decode(sharedenckeybase64, strlen((char *)sharedenckeybase64), sharedenckey,
                                       sharedenckeysize, &sharedenckeylen)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedenckeybase64 decode failed with code %d\n", res);
        atclient_atsign_free(&recipient);
        return res;
      }
      atclient_atsign_free(&recipient);
    }

    unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
    res = atchops_iv_generate(iv);
    if (res != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_iv_generate failed with code %d\n", res);
      return res;
    }

    res = atchops_base64_encode(iv, ATCHOPS_IV_BUFFER_SIZE, ivbase64, ivbase64size, &ivbase64len);
    if (res != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode failed with code %d\n", res);
      return res;
    }

    res = atclient_atkey_metadata_set_ivnonce(&(params->atkey->metadata), (char *)ivbase64, ivbase64len);
    if (res != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ivnonce failed with code %d\n", res);
      return res;
    }

    res = atchops_aesctr_encrypt(sharedenckey, ATCHOPS_AES_256, iv, (unsigned char *)params->value,
                                 strlen(params->value), ciphertext, ciphertextsize, &ciphertextlen);
    if (res != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt failed with code %d\n", res);
      return res;
    }

    res =
        atchops_base64_encode(ciphertext, ciphertextlen, ciphertextbase64, ciphertextbase64size, &ciphertextbase64len);
    if (res != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_encode failed with code %d\n", res);
      return res;
    }

    cmdvalue = malloc(sizeof(char) * (ciphertextbase64len + 1));
    memcpy(cmdvalue, ciphertextbase64, ciphertextbase64len);
    cmdvalue[ciphertextbase64len] = '\0';
    cmdvaluelen = ciphertextbase64len;
  } else if (params->value != NULL && !params->shouldencrypt) {
    cmdvaluelen = strlen(params->value);
    cmdvalue = malloc(sizeof(char) * (cmdvaluelen + 1));
    memcpy(cmdvalue, params->value, cmdvaluelen);
    cmdvalue[cmdvaluelen] = '\0';
  }

  size_t cmdlen = 0;

  res = generate_cmd(params, cmdvalue, cmdvaluelen, &cmd, &cmdlen);
  if (res != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "generate_cmd failed with code %d\n", res);
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

  res = atclient_connection_send(&(ctx->atserver_connection), (unsigned char *)cmd, cmdlen, recv, recvsize, &recvlen);
  if (res != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send failed with code %d\n", res);
    goto exit;
  } else if (ctx->async_read) {
    goto exit;
  }
  // if starts with data:
  if (atclient_stringutils_starts_with((char *)recv, recvlen, "data:", strlen("data:"))) {
    if (notification_id != NULL) { // if not null, then they care about the notification id
      // parse the notification id
      char *data = (char *)recv + strlen("data:");
      size_t datalen = recvlen - strlen("data:");
      if (datalen > 36) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Notification id too long\n");
        return 1;
      }
      strncpy(notification_id, data, datalen);
      notification_id[datalen] = '\0';
    }
    res = 0;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unexpected response: %.*s\n", (int)recvlen, recv);
    res = 1;
  }

exit: {
  if (!ctx->async_read) {
    free(recv);
  }
  free(cmdvalue);
  free(cmd);
  return res;
}
}

static size_t calculate_cmd_size(const atclient_notify_params *params, const size_t cmdvaluelen, size_t *atkeyolen,
                                 size_t *medatastrolen) {
  // notify command will look something like this:
  // "notify[:messageType:<type>][:priority:<priority>][:strategy:<strategy>][:ttln:<ttln>]<:atkey_metadata>:<atkey>[:<value>]\r\n"
  size_t cmdsize = 0;

  cmdsize += strlen("notify");

  if (strlen(params->id) > 0) {
    cmdsize += strlen(":id:") + strlen(params->id); // ":id:" + 36 char uuid
  }

  if (params->operation != ATCLIENT_NOTIFY_OPERATION_NONE) {
    cmdsize += strlen(":") + strlen(atclient_notify_operation_str[params->operation]); // ":update" | ":delete"
  }

  if (params->message_type != ATCLIENT_NOTIFY_MESSAGE_TYPE_NONE) {
    cmdsize += strlen(":messageType:") +
               strlen(atclient_notify_message_type_str[params->message_type]); // ":messageType" + ":text" | ":key"
  }

  if (params->priority != ATCLIENT_NOTIFY_PRIORITY_NONE) {
    cmdsize += strlen(":priority:") +
               strlen(atclient_notify_priority_str[params->priority]); // ":priority" + ":low" | ":medium" | ":high"
  }

  if (params->strategy != ATCLIENT_NOTIFY_STRATEGY_NONE) {
    cmdsize += strlen(":strategy:") +
               strlen(atclient_notify_strategy_str[params->strategy]); // ":strategy" + ":all" | ":latest"
  }

  if (params->notification_expiry > 0) {
    cmdsize += strlen(":ttln:") + long_strlen(params->notification_expiry); // :$ttln
  }

  const size_t metadatastrlen = atclient_atkey_metadata_protocol_strlen(&params->atkey->metadata);
  cmdsize += strlen(":") + metadatastrlen; // :$metadata

  const size_t atkeylen = atclient_atkey_strlen(params->atkey);
  cmdsize += strlen(":") + atkeylen; // :$atkey

  if (cmdvaluelen > 0) {
    cmdsize += strlen(":") + cmdvaluelen; // :$value
  }

  cmdsize += strlen("\r\n");

  cmdsize += 1; // null terminator

  *atkeyolen = atkeylen;
  *medatastrolen = metadatastrlen;

  return cmdsize;
}

static int generate_cmd(const atclient_notify_params *params, const char *cmdvalue, const size_t cmdvaluelen,
                        char **ocmd, size_t *ocmdolen) {
  int res = 1;

  char *cmd = NULL;
  char *metadatastr = NULL;

  size_t atkeylen = 0;
  size_t metadatastrlen = 0;

  size_t cmdsize = 0;

  cmdsize = calculate_cmd_size(params, cmdvaluelen, &atkeylen, &metadatastrlen);
  if (cmdsize <= 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "calculate_cmd_size failed with code %d\n", cmdsize);
    res = 1;
    goto exit;
  }

  // Step 3 allocate the buffer
  cmd = malloc(sizeof(char) * cmdsize);
  if (cmd == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "malloc failed\n");
    res = 1;
    goto exit;
  }
  memset(cmd, 0, sizeof(char) * cmdsize);

  // Step 4 build the command

  size_t off = 0;

  snprintf(cmd + off, cmdsize - off, "notify");
  off += strlen("notify");

  if (strlen(params->id) > 0) {
    snprintf(cmd + off, cmdsize - off, ":id:%s", params->id);
    off += strlen(":id:") + strlen(params->id);
  }

  if (params->operation != ATCLIENT_NOTIFY_OPERATION_NONE) {
    snprintf(cmd + off, cmdsize - off, ":%s", atclient_notify_operation_str[params->operation]);
    off += strlen(":") + strlen(atclient_notify_operation_str[params->operation]);
  }

  if (params->message_type != ATCLIENT_NOTIFY_MESSAGE_TYPE_NONE) {
    snprintf(cmd + off, cmdsize - off, ":messageType:%s", atclient_notify_message_type_str[params->message_type]);
    off += strlen(":messageType:") + strlen(atclient_notify_message_type_str[params->message_type]);
  }

  if (params->priority != ATCLIENT_NOTIFY_PRIORITY_NONE) {
    snprintf(cmd + off, cmdsize - off, ":priority:%s", atclient_notify_priority_str[params->priority]);
    off += strlen(":priority:") + strlen(atclient_notify_priority_str[params->priority]);
  }

  if (params->strategy != ATCLIENT_NOTIFY_STRATEGY_NONE) {
    snprintf(cmd + off, cmdsize - off, ":strategy:%s", atclient_notify_strategy_str[params->strategy]);
    off += strlen(":strategy:") + strlen(atclient_notify_strategy_str[params->strategy]);
  }

  if (params->notification_expiry > 0) {
    snprintf(cmd + off, cmdsize - off, ":ttln:%lu", params->notification_expiry);
    off += strlen(":ttln:") + long_strlen(params->notification_expiry);
  }

  size_t metadatastrolen;
  if ((res = atclient_atkey_metadata_to_protocol_str(&params->atkey->metadata, cmd + off, metadatastrlen,
                                                     &metadatastrolen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocol_str failed with code: %d\n",
                 res);
    goto exit;
  }
  if (metadatastrolen != metadatastrlen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "atclient_atkey_metadata_to_protocol_str mismatch. Expected %lu but got %lu\n", metadatastrlen,
                 metadatastrolen);
    res = 1;
    goto exit;
  }
  off += metadatastrolen;

  snprintf(cmd + off, metadatastrlen, ":");
  off += strlen(":");

  size_t atkeyolen;
  if ((res = atclient_atkey_to_string(params->atkey, cmd + off, atkeylen, &atkeyolen)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed with code: %d\n", res);
    return res;
  }
  if (atkeylen != atkeyolen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string mismatch. Expected %lu but got %lu\n",
                 atkeylen, atkeyolen);
    goto exit;
  }
  off += atkeylen;

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
  free(metadatastr);
  return res;
}
}
