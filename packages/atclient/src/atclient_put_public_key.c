#include <atchops/aes_ctr.h>
#include <atchops/base64.h>
#include <atchops/iv.h>
#include <atclient/atclient.h>
#include <atclient/atkey.h>
#include <atclient/request_options.h>
#include <atclient/string_utils.h>
#include <atlogger/atlogger.h>
#include <stdlib.h>
#include <string.h>

#define TAG "atclient_put_public_key"

static int atclient_put_public_key_validate_arguments(const atclient *ctx, const atclient_atkey *atkey,
                                                      const char *value,
                                                      const atclient_put_public_key_request_options *request_options,
                                                      const int *commit_id);

int atclient_put_public_key(atclient *ctx, atclient_atkey *atkey, const char *value,
                            const atclient_put_public_key_request_options *request_options, int *commit_id) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if ((ret = atclient_put_public_key_validate_arguments(ctx, atkey, value, request_options, commit_id)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put_public_key_validate_arguments: %d\n", ret);
    return ret;
  }

  /*
   * 2. Variables
   */
  char *atkey_str = NULL;
  char *metadata_protocol_str = NULL;
  char *update_cmd = NULL;

  const size_t recv_size = 256;
  unsigned char *recv = NULL;
  if (!ctx->async_read) {
    if ((recv = malloc(sizeof(unsigned char) * recv_size)) == NULL) {
      ret = 1;
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for recv\n");
      goto exit;
    }
    memset(recv, 0, sizeof(unsigned char) * recv_size);
  }
  size_t recv_len = 0;

  /*
   * 3. Build update command
   */
  if ((ret = atclient_atkey_to_string(atkey, &atkey_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_atkey_metadata_to_protocol_str(&(atkey->metadata), &metadata_protocol_str)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocol_str: %d\n", ret);
    goto exit;
  }

  const size_t atkey_str_len = strlen(atkey_str);
  const size_t metadata_protocol_str_len = strlen(metadata_protocol_str);

  const size_t update_cmd_size = strlen("update") + metadata_protocol_str_len + strlen(":") + atkey_str_len +
                                 strlen(" ") + strlen(value) + strlen("\r\n") + 1;
  if ((update_cmd = malloc(sizeof(char) * update_cmd_size)) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for update_cmd\n");
    goto exit;
  }
  snprintf(update_cmd, update_cmd_size, "update%s:%s %s\r\n", metadata_protocol_str, atkey_str, value);
  const size_t update_cmd_len = update_cmd_size - 1;

  /*
   * 4. Send update command
   */
  if ((ret = atclient_connection_send(&ctx->atserver_connection, (unsigned char *)update_cmd, update_cmd_len, recv,
                                      recv_size, &recv_len)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (ctx->async_read) {
    goto exit;
  }

  char *response = (char *)recv;

  if (!atclient_string_utils_starts_with(response, "data:")) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                 (int)recv_len, recv);
    goto exit;
  }

  char *response_without_data = response + strlen("data:");

  /*
   * 5. Receive commit id
   */
  if (commit_id != NULL) {
    *commit_id = atoi(response_without_data);
  }

  ret = 0;
  goto exit;
exit: {
  free(recv);
  free(atkey_str);
  free(metadata_protocol_str);
  free(update_cmd);
  return ret;
}
}

static int atclient_put_public_key_validate_arguments(const atclient *ctx, const atclient_atkey *atkey,
                                                      const char *value,
                                                      const atclient_put_public_key_request_options *request_options,
                                                      const int *commit_id) {
  int ret = 1;

  char *client_atsign_with_at = NULL;
  char *shared_by_atsign_with_at = NULL;

  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ctx is NULL\n");
    goto exit;
  }

  // TODO atclient checks

  if (atkey == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey is NULL\n");
    goto exit;
  }

  if (value == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value is NULL\n");
    goto exit;
  }

  const atclient_atkey_type atkey_type = atclient_atkey_get_type(atkey);

  if (atkey_type != ATCLIENT_ATKEY_TYPE_PUBLIC_KEY) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey_type is not ATKEY_TYPE_PUBLICKEY\n");
    goto exit;
  }

  if (!atclient_atkey_is_key_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_is_key_initialized is false\n");
    goto exit;
  }

  if (!atclient_atkey_is_shared_by_initialized(atkey)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_is_shared_by_initialized is false\n");
    goto exit;
  }

  if ((ret = atclient_string_utils_atsign_with_at(ctx->atsign, &client_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at failed\n");
    goto exit;
  }

  if ((ret = atclient_string_utils_atsign_with_at(atkey->shared_by, &shared_by_atsign_with_at)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_string_utils_atsign_with_at failed\n");
    goto exit;
  }

  if (strcmp(client_atsign_with_at, shared_by_atsign_with_at) != 0) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                 "client_atsign_with_at and shared_by_atsign_with_at are not equal\n");
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  free(client_atsign_with_at);
  free(shared_by_atsign_with_at);
  return ret;
}
}
