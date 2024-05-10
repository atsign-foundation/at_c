#include "atclient/notify.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "atclient/encryption_key_helpers.h"
#include "atclient/stringutils.h"
#include "cJSON.h"
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

#define TAG "atclient_notify"

void atclient_notify_params_init(atclient_notify_params *params) {
  memset(params, 0, sizeof(atclient_notify_params));
  params->message_type = ATCLIENT_NOTIFY_MESSAGE_TYPE_KEY;
  params->priority = ATCLIENT_NOTIFY_PRIORITY_LOW;
  params->strategy = ATCLIENT_NOTIFY_STRATEGY_ALL;
  params->latest_n = 1;
  params->value = NULL;
  params->shouldencrypt = true;
  params->notifier = ATCLIENT_DEFAULT_NOTIFIER;
  params->notification_expiry = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
}

void atclient_notify_params_create(atclient_notify_params *params, enum atclient_notify_operation operation,
                                   atclient_atkey *atkey, const char *value, bool shouldencrypt) {
  params->operation = operation;
  params->key = *atkey;
  params->value = value;
  params->shouldencrypt = shouldencrypt;
}

void atclient_notify_params_free(atclient_notify_params *params) { memset(params, 0, sizeof(atclient_notify_params)); }

int atclient_notify(atclient *ctx, atclient_notify_params *params, char *notification_id) {
  int res = 1;
  // Step 1 calculate the buffer size needed for the protocol command
  // size_t cmdsize = 6 + 3 +                               // "notify" (6) + "\r\n\0" (3)
  //                  1 + 8 + 1 + strlen(params->notifier); // ":" (1) + "notifier" (8) + ":" (1) + "$notifier" (strlen)

  // if (params->id != NULL) {
  //   cmdsize += 1 + 2 + 1 + strlen(params->id); // ":id:" + 36 char uuid
  // }

  // if (params->operation != ATCLIENT_NOTIFY_OPERATION_UPDATE) {
  //   cmdsize += 1 + 6; // ":update" | ":delete"
  // }

  // if (params->message_type != ATCLIENT_NOTIFY_MESSAGE_TYPE_NONE) {
  //   cmdsize += 1 + 11 + 1 + 4; // ":messageType" + ":text" | ":key"
  // }

  // if (params->priority != ATCLIENT_NOTIFY_PRIORITY_NONE) {
  //   cmdsize += 1 + 8 + 1 + 6; // ":priority" + ":low" | ":medium" | ":high"
  // }

  // if (params->strategy != ATCLIENT_NOTIFY_STRATEGY_NONE) {
  //   cmdsize += 1 + 8 + 1 + 6; // ":strategy" + ":all" | ":latest"
  // }

  // if (params->notification_expiry > 0) {
  //   cmdsize += 1 + 4 + 1 + // ":ttln:"
  //              20;         // epochMillis (20 digits covers all 2^64 of unsigned long long, good for 300,000+ years)
  // }

  // if (params->value != NULL) {
  //   cmdsize += 1 + strlen(params->value); // :$value
  // }

  // // add metadata fragment length
  // size_t metadatalen = atclient_atkey_metadata_protocol_strlen(&params->key.metadata);
  // cmdsize += metadatalen;

  // atkey parts length
  size_t atkeylen = atclient_atkey_strlen(&params->key);
  // cmdsize += 1 + atkeylen; // :$atkey

  struct timeval tv;
  res = gettimeofday(&tv, NULL);
  if (res != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 // TODO: get errno
                 "gettimeofday failed with code stored in errno %d\n", res);
    return res;
  }

  unsigned long long ttln =
      (unsigned long long)(tv.tv_sec) * 1000 + (unsigned long long)(tv.tv_usec) / 1000 + params->notification_expiry;

  // Step 3 allocate the buffer and populate the full command
  const char *part;
  size_t off = 0;

  size_t cmdsize = 4096;
  char cmd[cmdsize];
  memset(cmd, 0, sizeof(char) * cmdsize);

  snprintf(cmd + off, cmdsize - off, "notify");
  off += strlen("notify");

  if (params->id != NULL && strlen(params->id) > 0) {
    snprintf(cmd + off, cmdsize - off, ":id:%s", params->id);
    off += 1 + 2 + 1 + strlen(params->id);
  }

  if (params->operation != ATCLIENT_NOTIFY_OPERATION_UPDATE) {
    part = atclient_notify_operation_str[params->operation];
    snprintf(cmd + off, cmdsize - off, ":%s", part);
    off += 1 + strlen(part);
  }

  if (params->message_type != ATCLIENT_NOTIFY_MESSAGE_TYPE_NONE) {
    part = atclient_notify_message_type_str[params->message_type];
    snprintf(cmd + off, cmdsize - off, ":messageType:%s", part);
    off += 13 + strlen(part);
  }

  if (params->priority != ATCLIENT_NOTIFY_PRIORITY_NONE) {
    part = atclient_notify_priority_str[params->priority];
    snprintf(cmd + off, cmdsize - off, ":priority:%s", part);
    off += 10 + strlen(part);
  }

  if (params->strategy != ATCLIENT_NOTIFY_STRATEGY_NONE) {
    part = atclient_notify_strategy_str[params->strategy];
    snprintf(cmd + off, cmdsize - off, ":strategy:%s", part);
    off += 10 + strlen(part);
  }

  if (params->notification_expiry > 0) {
    int ttln_len = long_strlen(ttln);
    snprintf(cmd + off, cmdsize - off, ":ttln:%llu", ttln);
    off += 6 + ttln_len;
  }

  const size_t ciphertextsize = MAX(strlen(params->value) * 2, 128); // TODO optimize
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  const size_t ciphertextbase64size = MAX(ciphertextsize * 2, 128); // TODO optimize
  unsigned char ciphertextbase64[ciphertextbase64size];
  memset(ciphertextbase64, 0, sizeof(unsigned char) * ciphertextbase64size);
  size_t ciphertextbase64len = 0;

  const size_t ivbase64size = 32;
  unsigned char ivbase64[ivbase64size];
  memset(ivbase64, 0, sizeof(unsigned char) * ivbase64size);
  size_t ivbase64len = 0;

  if (params->value != NULL && params->shouldencrypt) {
    const size_t sharedenckeysize = 32;
    unsigned char sharedenckey[sharedenckeysize];
    memset(sharedenckey, 0, sizeof(unsigned char) * sharedenckeysize);
    size_t sharedenckeylen;

    if (params->sharedenckeybase64 != NULL) {
      res = atchops_base64_decode(params->sharedenckeybase64, strlen(params->sharedenckeybase64), sharedenckey,
                                  sharedenckeysize, &sharedenckeylen);
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
      unsigned char sharedenckeybase64[45];
      memset(sharedenckeybase64, 0, sizeof(unsigned char) * 45);
      if ((res = atclient_atsign_init(&recipient, params->key.sharedwith.str)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atsign_init failed with code %d\n", res);
        return res;
      }
      if ((res = atclient_get_shared_encryption_key_shared_by_me(ctx, &recipient, sharedenckeybase64, true)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                     "atclient_get_shared_encryption_key_shared_by_me failed with code %d\n", res);
        return res;
      }
      if ((res = atchops_base64_decode(sharedenckeybase64, strlen(sharedenckeybase64), sharedenckey, sharedenckeysize,
                                       &sharedenckeylen)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "sharedenckeybase64 decode failed with code %d\n", res);
        return res;
      }
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

    res = atclient_atkey_metadata_set_ivnonce(&params->key.metadata, ivbase64, ivbase64len);
    if (res != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_set_ivnonce failed with code %d\n", res);
      return res;
    }

    res = atchops_aesctr_encrypt(sharedenckey, ATCHOPS_AES_256, iv, params->value, strlen(params->value), ciphertext,
                                 ciphertextsize, &ciphertextlen);
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
  }

  const size_t metadatastrsize = atclient_atkey_metadata_protocol_strlen(&params->key.metadata);
  char metadatastr[metadatastrsize];
  memset(metadatastr, 0, sizeof(char) * metadatastrsize);
  size_t metadatastrlen = 0;
  res = atclient_atkey_metadata_to_protocol_str(&params->key.metadata, metadatastr, metadatastrsize, &metadatastrlen);
  if (res != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocol_str failed with code %d\n",
                 res);
    return res;
  }

  snprintf(cmd + off, cmdsize - off, "%s", metadatastr);
  off += metadatastrlen;

  // ':' before the atkey
  cmd[off] = ':';
  off += 1;

  size_t atkeyolen;
  atclient_atkey_to_string(&params->key, cmd + off, atkeylen, &atkeyolen);
  if (atkeylen != atkeyolen) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string mismatch. Expected %lu but got %lu\n",
                 atkeylen, atkeyolen);
    return 1;
  }
  off += atkeylen;

  // Step 6 send the encrypted notification
  if(params->shouldencrypt)
  {
    snprintf(cmd + off, cmdsize - off, ":%s", ciphertextbase64);
    off += 1 + ciphertextbase64len;
  } else {
    snprintf(cmd + off, cmdsize - off, ":%s", params->value);
    off += 1 + strlen(params->value);
  }

  snprintf(cmd + off, cmdsize - off, "\r\n");
  off += 2;

  const size_t recvsize = 64;
  unsigned char recv[recvsize];
  memset(recv, 0, sizeof(unsigned char) * recvsize);
  size_t recvlen = 0;

  res = atclient_connection_send(&(ctx->secondary_connection), cmd, strlen(cmd), recv, recvsize, &recvlen);
  if (res != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send failed with code %d\n", res);
    return res;
  }

  // if starts with data:
  if (atclient_stringutils_starts_with(recv, recvlen, "data:", strlen("data:"))) {
    if (notification_id != NULL) { // if not null, then they care about the notification id
      // parse the notification id
      char *data = recv + strlen("data:");
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

  return res;
}
