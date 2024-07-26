#include "atclient/atclient.h"
#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atclient/string_utils.h"
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_get_publickey"

static int atclient_get_public_key_validate_arguments(atclient *atclient, atclient_atkey *atkey, char *value,
                                                     const size_t value_size, size_t *value_len, bool bypass_cache);

int atclient_get_public_key(atclient *atclient, atclient_atkey *atkey, char *value, const size_t value_size,
                           size_t *value_len, bool bypass_cache) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_get_public_key_validate_arguments(atclient, atkey, value, value_size, value_len, bypass_cache)) !=
      0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_public_key_validate_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Initialize variables
   */
  char *atkey_str = NULL;

  const size_t recv_size = value_size;
  unsigned char recv[recv_size];
  memset(recv, 0, sizeof(unsigned char) * recv_size);
  size_t recv_len = 0;

  cJSON *root = NULL;
  char *plookup_cmd = NULL;
  char *metadata_str = NULL;

  /*
   * 3. Build `plookup:` command
   */
  if ((ret = atclient_atkey_to_string(atkey, &atkey_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  char *atkey_str_without_public = NULL;
  char *ptr = strstr(atkey_str, "public:");
  if (ptr != NULL) {
    atkey_str_without_public = ptr + strlen("public:");
  } else {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not find \"public:\" from string \"%s\"\n", atkey_str);
    goto exit;
  }

  const size_t plookup_cmd_size = strlen("plookup:all:\r\n") + (bypass_cache ? strlen("bypassCache:true:") : 0) +
                                  strlen(atkey_str_without_public) + 1;
  plookup_cmd = malloc(sizeof(char) * plookup_cmd_size);
  if (plookup_cmd == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for plookup_cmd\n");
    goto exit;
  }
  memset(plookup_cmd, 0, plookup_cmd_size);
  snprintf(plookup_cmd, plookup_cmd_size, "plookup:%sall:%s\r\n", bypass_cache ? "bypassCache:true:" : "",
           atkey_str_without_public);
  const size_t cmdbufferlen = strlen(plookup_cmd);

  /*
   * 4. Send `plookup:` command
   */
  if ((ret = atclient_connection_send(&(atclient->atserver_connection), (unsigned char *)plookup_cmd, cmdbufferlen,
                                      recv, recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  /*
   * 5. Parse response
   */
  char *response = (char *)recv;
  if (!atclient_string_utils_starts_with(response, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  char *response_without_data = response + 5;

  root = cJSON_Parse(response_without_data);
  if (root == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
    goto exit;
  }

  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  /*
   * 6. Return data to caller
   */
  memcpy(value, data->valuestring, strlen(data->valuestring));
  *value_len = strlen(value);

  // 6b. write to atkey->metadata
  cJSON *metadata = cJSON_GetObjectItem(root, "metaData");
  if (metadata == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  metadata_str = cJSON_Print(metadata);

  if ((ret = atclient_atkey_metadata_from_json_str(&(atkey->metadata), metadata_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_json_str: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  if (root != NULL) {
    cJSON_Delete(root);
  }
  free(metadata_str);
  free(plookup_cmd);
  free(atkey_str);
  return ret;
}
}

static int atclient_get_public_key_validate_arguments(atclient *atclient, atclient_atkey *atkey, char *value,
                                                     const size_t value_size, size_t *value_len, bool bypass_cache) {
  int ret = 1;

  if (atclient == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient is NULL\n");
    goto exit;
  }

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_PUBLIC_KEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is not a public key\n");
    goto exit;
  }

  if (value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    goto exit;
  }

  if (value_size == 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value_size is 0\n");
    goto exit;
  }

  if (value_len == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value_len is NULL\n");
    goto exit;
  }

  if (!atclient_is_atserver_connection_started(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atserver connection not started\n");
    goto exit;
  }

  if (!atclient_is_atsign_initialized(atclient)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsign not initialized\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}