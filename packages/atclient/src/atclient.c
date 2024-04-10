#include "atclient/atclient.h"
#include "atchops/aes.h"
#include "atchops/aesctr.h"
#include "atchops/base64.h"
#include "atchops/iv.h"
#include "atchops/rsa.h"
#include "atclient/atbytes.h"
#include "atclient/atkey.h"
#include "atclient/atkeys.h"
#include "atclient/atsign.h"
#include "atclient/atstr.h"
#include "atclient/connection.h"
#include "atclient/constants.h"
#include "atclient/stringutils.h"
#include "atlogger/atlogger.h"
#include <cjson/cJSON.h>
#include <mbedtls/md.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOST_BUFFER_SIZE 1024 // the size of the buffer for the host name for root and secondary

#define ATCLIENT_ERR_AT0015_KEY_NOT_FOUND -0x1980

#define TAG "atclient"

void atclient_init(atclient *ctx) { memset(ctx, 0, sizeof(atclient)); }

int atclient_start_root_connection(atclient_connection *root_conn, const char *roothost, const int rootport) {
  int ret = 1; // error by default

  atclient_connection_init(root_conn);

  ret = atclient_connection_connect(root_conn, roothost, rootport);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }
  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                        "atclient_connection_connect: %d. Successfully connected to root\n", ret);

  goto exit;

exit : { return ret; }
}

int atclient_start_secondary_connection(atclient *ctx, const char *secondaryhost, const int secondaryport) {
  int ret = 1; // error by default

  atclient_connection_init(&(ctx->secondary_connection));
  ret = atclient_connection_connect(&(ctx->secondary_connection), secondaryhost, secondaryport);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_connect: %d\n", ret);
    goto exit;
  }
  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO,
                        "atclient_connection_connect: %d. Successfully connected to secondary\n", ret);

  goto exit;

exit : { return ret; }
}

int atclient_pkam_authenticate(atclient *ctx, atclient_connection *root_conn, const atclient_atkeys atkeys,
                               const atclient_atsign *atsign) {
  int ret = 1; // error by default

  char *root_command = NULL;
  char *from_command = NULL;
  char *pkam_command = NULL;

  // 1. init root connection
  const size_t srclen = 1024;
  atclient_atbytes src;
  atclient_atbytes_init(&src, srclen);

  const size_t recvlen = 1024;
  atclient_atbytes recv;
  atclient_atbytes_init(&recv, recvlen);

  const size_t urllen = 256;
  atclient_atstr url;
  atclient_atstr_init(&url, 256);

  atclient_atstr host;
  atclient_atstr_init(&host, 256);
  int port = 0;

  const size_t atsigncmdlen = 1024;
  atclient_atstr atsigncmd;
  atclient_atstr_init(&atsigncmd, atsigncmdlen);

  const size_t fromcmdlen = 1024;
  atclient_atstr fromcmd;
  atclient_atstr_init(&fromcmd, fromcmdlen);

  const size_t challengelen = 1024;
  atclient_atstr challenge;
  atclient_atstr_init(&challenge, challengelen);

  const size_t challengewithoutdatalen = 1024;
  atclient_atstr challengewithoutdata;
  atclient_atstr_init(&challengewithoutdata, challengewithoutdatalen);

  const size_t challengebyteslen = 1024;
  atclient_atbytes challengebytes;
  atclient_atbytes_init(&challengebytes, challengebyteslen);

  const size_t pkamcmdlen = 1024;
  atclient_atstr pkamcmd;
  atclient_atstr_init(&pkamcmd, pkamcmdlen);

  // build command, ie atsign without "@"
  const short root_command_len = strlen(atsign->without_prefix_str) + 3;
  root_command = calloc(root_command_len, sizeof(char));
  snprintf(root_command, root_command_len, "%s\r\n", atsign->without_prefix_str);

  ret = atclient_connection_send(root_conn, (unsigned char *)root_command, root_command_len - 1, recv.bytes, recv.len,
                                 &(recv.olen));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n | failed to send: %.*s\n",
                          ret, root_command_len, root_command);
    goto exit;
  }

  // 2. init secondary connection
  // recv is something like 3b419d7a-2fee-5080-9289-f0e1853abb47.swarm0002.atsign.zone:5770
  // store host and port in separate vars
  ret = atclient_atstr_set_literal(&url, "%.*s", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_get_host_and_port(&host, &port, url);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_connection_get_host_and_port: %d | failed to parse url %.*s\n", ret, recv.olen,
                          recv.bytes);
    goto exit;
  }

  ret = atclient_start_secondary_connection(ctx, host.str, port);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_start_secondary_connection: %d\n", ret);
    goto exit;
  }

  // 3. send pkam auth
  // build command, ie "from:atsign"
  const short from_command_len = 5 + root_command_len; // "from:" has a length of 5
  from_command = calloc(from_command_len, sizeof(char));
  snprintf(from_command, from_command_len, "from:%s", root_command);

  ret = atclient_connection_send(&(ctx->secondary_connection), (unsigned char *)from_command, from_command_len - 1,
                                 recv.bytes, recv.len, &(recv.olen));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set_literal(&challenge, "%.*s", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  // remove "data:" prefix
  ret = atclient_atstr_substring(&challengewithoutdata, challenge, 5, challenge.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atclient_atstr_substring: %d\n | failed to remove \'data:\' prefix", ret);
    goto exit;
  }

  // sign
  atclient_atbytes_reset(&recv);
  ret = atclient_atbytes_convert_atstr(&challengebytes, challengewithoutdata);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
    goto exit;
  }
  ret = atchops_rsa_sign(atkeys.pkamprivatekey, MBEDTLS_MD_SHA256, challengebytes.bytes, challengebytes.olen,
                         recv.bytes, recv.len, &recv.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_sign: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_set_literal(&pkamcmd, "pkam:%.*s\r\n", (int)recv.olen, recv.bytes);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal: %d\n", ret);
    goto exit;
  }

  atclient_atbytes_reset(&recv);
  ret = atclient_atbytes_convert_atstr(&src, pkamcmd);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atbytes_convert_atstr: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_send(&(ctx->secondary_connection), src.bytes, src.olen, recv.bytes, recv.len, &recv.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // check for data:success
  if (!atclient_stringutils_starts_with((char *)recv.bytes, recv.olen, "data:success", strlen("data:success"))) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "recv was \"%.*s\" and did not have prefix \"data:success\"\n", (int)recv.olen, recv.bytes);
    goto exit;
  }

  ret = 0;

  goto exit;
exit : {
  atclient_atbytes_free(&src);
  atclient_atbytes_free(&recv);
  atclient_atstr_free(&url);
  atclient_atstr_free(&host);
  atclient_atstr_free(&atsigncmd);
  atclient_atstr_free(&fromcmd);
  atclient_atstr_free(&challenge);
  atclient_atstr_free(&challengewithoutdata);
  atclient_atbytes_free(&challengebytes);
  atclient_atstr_free(&pkamcmd);
  return ret;
}
}

int atclient_put(atclient *atclient, atclient_connection *root_conn, const atclient_atkey *atkey, const char *value,
                 const size_t valuelen, int *commitid) {
  int ret = 1;

  // 1. initialize variables
  const size_t atkeystrlen = ATCLIENT_ATKEY_FULL_LEN;
  char atkeystr[atkeystrlen];
  memset(atkeystr, 0, sizeof(char) * atkeystrlen);
  size_t atkeystrolen = 0;

  const size_t recvlen = 4096;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t recvolen = 0;

  const size_t ivlen = ATCHOPS_IV_BUFFER_SIZE;
  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
  memset(iv, 0, sizeof(unsigned char) * ivlen);

  const size_t metadataprotocolstrlen = 2048;
  char metadataprotocolstr[metadataprotocolstrlen];
  memset(metadataprotocolstr, 0, sizeof(char) * metadataprotocolstrlen);
  size_t metadataprotocolstrolen = 0;

  const size_t ciphertextlen = 4096;
  unsigned char ciphertext[4096];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextlen);
  size_t ciphertextolen = 0;

  char *cmdbuffer = NULL;

  // 2. build update: command
  ret = atclient_atkey_to_string(atkey, atkeystr, atkeystrlen, &atkeystrolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  ret = atclient_atkey_metadata_to_protocol_str(&atkey->metadata, metadataprotocolstr, metadataprotocolstrlen,
                                                &metadataprotocolstrolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_to_protocolstr: %d\n", ret);
    goto exit;
  }

  if (atkey->atkeytype == ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    // no encryption
    memcpy(ciphertext, value, valuelen);
    ciphertextolen = valuelen;
  } else if (atkey->atkeytype == ATCLIENT_ATKEY_TYPE_SELFKEY) {
    // encrypt with self encryption key
    ret = atchops_aesctr_encrypt(atclient->atkeys.selfencryptionkeystr.str, atclient->atkeys.selfencryptionkeystr.olen,
                                 ATCHOPS_AES_256, iv, (unsigned char *)value, valuelen, ciphertext, ciphertextlen,
                                 &ciphertextolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_encrypt: %d\n", ret);
      goto exit;
    }
  } else if (atkey->atkeytype == ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    // TODO: implement, encrypt with some shared AES symmetric encryption key
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ATCLIENT_ATKEY_TYPE_SHAREDKEY not implemented in put\n");
    ret = 1;
    goto exit;
  }

  size_t cmdbufferlen = strlen(" update:\r\n") + atkeystrolen + ciphertextolen + 1; // + 1 for null terminator

  if (metadataprotocolstrolen > 0) {
    cmdbufferlen += metadataprotocolstrolen;
  }
  cmdbuffer = malloc(sizeof(char) * cmdbufferlen);
  memset(cmdbuffer, 0, sizeof(char) * cmdbufferlen);

  snprintf(cmdbuffer, cmdbufferlen, "update%.*s:%.*s %.*s\r\n", (int)metadataprotocolstrolen, metadataprotocolstr,
           (int)atkeystrolen, atkeystr, (int)ciphertextolen, ciphertext);

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer, cmdbufferlen - 1, recv,
                                 recvlen, &recvolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_stringutils_starts_with((char *)recv, recvolen, "data:", 5)) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                          (int)recvolen, recv);
    goto exit;
  }

  if (commitid != NULL) {
    char *recvwithoutdata = (char *)recv + 5;
    *commitid = atoi(recvwithoutdata);
  }

  ret = 0;
  goto exit;
exit : {

  free(cmdbuffer);
  return ret;
}
}

int atclient_get_selfkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuelen,
                         size_t *valueolen) {
  if (atkey->atkeytype != ATCLIENT_ATKEY_TYPE_SELFKEY) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->atkeytype != ATKEYTYPE_SELF\n");
    return 1;
  }

  int ret = 1;

  // 1. initialize variables
  const size_t atkeystrlen = ATCLIENT_ATKEY_FULL_LEN;
  char atkeystr[atkeystrlen];
  memset(atkeystr, 0, sizeof(char) * atkeystrlen);
  size_t atkeystrolen = 0;

  const size_t recvlen = 4096;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t recvolen = 0;

  unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];

  cJSON *root = NULL;
  char *cmdbuffer = NULL;

  // 2. build llookup: command
  ret = atclient_atkey_to_string(atkey, atkeystr, atkeystrlen, &atkeystrolen);

  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  const size_t cmdbufferlen = strlen("llookup:all:\r\n") + atkeystrolen + 1;
  cmdbuffer = malloc(sizeof(char) * cmdbufferlen);
  memset(cmdbuffer, 0, cmdbufferlen);

  snprintf(cmdbuffer, cmdbufferlen, "llookup:all:%.*s\r\n", (int)atkeystrolen, atkeystr);

  atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "cmdbuffer: %.*s\n", (int)cmdbufferlen, cmdbuffer);

  // 3. send llookup: command
  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer, cmdbufferlen - 1, recv,
                                 recvlen, &recvolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // 4. parse response
  if (!atclient_stringutils_starts_with((char *)recv, recvolen, "data:", 5)) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                          (int)recvolen, recv);
    goto exit;
  }

  char *recvwithoutdata = (char *)recv + 5;

  root = cJSON_Parse(recvwithoutdata);
  if (root == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
    goto exit;
  }

  cJSON *metadata = cJSON_GetObjectItem(root, "metaData");
  if (metadata == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  char *metadatastr = cJSON_Print(metadata);

  ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr, strlen(metadatastr));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
    goto exit;
  }

  if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
    size_t ivolen;
    ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce.str, atkey->metadata.ivnonce.olen, iv,
                                ATCHOPS_IV_BUFFER_SIZE, &ivolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
      goto exit;
    }

    if (ivolen != ATCHOPS_IV_BUFFER_SIZE) {
      ret = 1;
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivolen != ivlen (%d != %d)\n", ivolen,
                            ATCHOPS_IV_BUFFER_SIZE);
      goto exit;
    }
  } else {
    // use legacy IV
    memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  }

  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  ret = atchops_aesctr_decrypt(atclient->atkeys.selfencryptionkeystr.str, atclient->atkeys.selfencryptionkeystr.olen,
                               ATCHOPS_AES_256, iv, (unsigned char *)data->valuestring, strlen(data->valuestring),
                               (unsigned char *)value, valuelen, valueolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit : { return ret; }
}

int atclient_get_publickey(atclient *atclient, atclient_connection *root_conn, atclient_atkey *atkey, char *value,
                           const size_t valuelen, size_t *valueolen, bool bypasscache) {
  int ret = 1;

  if (atkey->atkeytype != ATCLIENT_ATKEY_TYPE_PUBLICKEY) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->atkeytype != ATKEYTYPE_PUBLIC\n");
    return 1;
  }

  // 1. initialize variables
  const size_t atkeystrlen = ATCLIENT_ATKEY_FULL_LEN;
  atclient_atstr atkeystr;
  atclient_atstr_init(&atkeystr, atkeystrlen);

  const size_t recvlen = 4096;
  atclient_atbytes recv;
  atclient_atbytes_init(&recv, recvlen);

  cJSON *root = NULL;
  char *cmdbuffer = NULL;
  char *metadatastr = NULL;

  // 2. build plookup: command
  ret = atclient_atkey_to_string(atkey, atkeystr.str, atkeystr.len, &atkeystr.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  char *bypasscachestr = NULL;
  if (bypasscache) {
    bypasscachestr = "bypassCache:true:";
  }

  char *atkeystrwithoutpublic = NULL;
  char *ptr = strstr(atkeystr.str, "public:");
  if (ptr != NULL) {
    atkeystrwithoutpublic = ptr + strlen("public:");
  } else {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Could not find \"public:\" from string \"%s\"\n",
                          atkeystr.str);
    goto exit;
  }

  const size_t cmdbufferlen = strlen("plookup:all:\r\n") + (bypasscachestr != NULL ? strlen(bypasscachestr) : 0) +
                              strlen(atkeystrwithoutpublic) + 1;
  cmdbuffer = malloc(sizeof(char) * cmdbufferlen);
  memset(cmdbuffer, 0, cmdbufferlen);
  snprintf(cmdbuffer, cmdbufferlen, "plookup:%sall:%s\r\n", bypasscachestr != NULL ? bypasscachestr : "",
           atkeystrwithoutpublic);
  const size_t cmdbufferolen = strlen(cmdbuffer);

  // 3. send plookup: command
  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer, cmdbufferolen,
                                 recv.bytes, recv.len, &recv.olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  // 4. parse response

  // 4a. if recv does not start with "data:", we probably got an error
  if (!atclient_stringutils_starts_with((char *)recv.bytes, recv.olen, "data:", 5)) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                          (int)recv.olen, recv.bytes);
    goto exit;
  }

  char *recvwithoutdata = (char *)recv.bytes + 5;

  root = cJSON_Parse(recvwithoutdata);
  if (root == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
    goto exit;
  }

  // 4b. set *value and *valueolen
  cJSON *data = cJSON_GetObjectItem(root, "data");
  if (data == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  memset(value, 0, valuelen);
  memcpy(value, data->valuestring, strlen(data->valuestring));
  *valueolen = strlen(value);

  // 4c. write to atkey->metadata
  cJSON *metadata = cJSON_GetObjectItem(root, "metaData");
  if (metadata == NULL) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
    goto exit;
  }

  metadatastr = cJSON_Print(metadata);

  ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr, strlen(metadatastr));
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit : {
  if (root != NULL) {
    cJSON_Delete(root);
  }
  free(metadatastr);
  free(cmdbuffer);
  return ret;
}
}

static int
atclient_get_sharedkey_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char *value,
                                               const size_t valuelen, size_t *valueolen, char *shared_enc_key,
                                               const bool create_new_encryption_key_shared_by_me_if_not_found);

static int atclient_get_sharedkey_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuelen, size_t *valueolen,
                                                          char *shared_enc_key);

int atclient_get_sharedkey(atclient *atclient, atclient_atkey *atkey, char *value, const size_t valuelen,
                           size_t *valueolen, char *shared_enc_key,
                           const bool create_new_encryption_key_shared_by_me_if_not_found) {
  int ret = 1;

  if (atkey->atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atkey->atkeytype != ATCLIENT_ATKEY_TYPE_SHAREDKEY\n");
    return ret;
  }

  if (strncmp(atkey->sharedby.str, atclient->atsign.atsign, atkey->sharedby.olen) != 0) {
    //  && (!atkey->metadata.iscached && !atkey->metadata.ispublic)
    ret = atclient_get_sharedkey_shared_by_other_with_me(atclient, atkey, value, valuelen, valueolen, shared_enc_key);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_sharedkey_shared_by_other_with_me: %d\n",
                            ret);
      goto exit;
    }
  } else {
    ret = atclient_get_sharedkey_shared_by_me_with_other(atclient, atkey, value, valuelen, valueolen, shared_enc_key,
                                                         false);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_sharedkey_shared_by_me_with_other: %d\n",
                            ret);
      goto exit;
    }
  }

  goto exit;
exit : { return ret; }
}

static int
atclient_get_sharedkey_shared_by_me_with_other(atclient *atclient, atclient_atkey *atkey, char *value,
                                               const size_t valuelen, size_t *valueolen, char *shared_enc_key,
                                               const bool create_new_encryption_key_shared_by_me_if_not_found) {
  int ret = 1;
  short enc_key_mem = 0;

  char *atkey_str_buff = NULL;
  char *command = NULL;
  char *response_prefix = NULL;
  unsigned char *recv = NULL;

  // check shared key
  char *enc_key = shared_enc_key;
  if (enc_key == NULL) {
    enc_key_mem = 1;
    enc_key = malloc(45);
    atclient_atsign recipient;
    ret = atclient_atsign_init(&recipient, atkey->sharedwith.str);
    if (ret != 0) {
      goto exit;
    }
    ret = atclient_get_encryption_key_shared_by_me(atclient, &recipient, enc_key,
                                                   create_new_encryption_key_shared_by_me_if_not_found);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
  }

  // atclient_atkey_to_string buffer
  const size_t atkey_str_buf_len = 4096;
  atkey_str_buff = calloc(atkey_str_buf_len, sizeof(char));
  size_t atkey_out_len = 0;

  ret = atclient_atkey_to_string(atkey, atkey_str_buff, atkey_str_buf_len, &atkey_out_len);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  // build command
  // command_prefix = "llookup:all:"
  const short command_prefix_len = 12;

  const size_t command_len = command_prefix_len + atkey_out_len + 3;
  command = malloc(command_len * sizeof(char));
  snprintf(command, command_len, "llookup:all:%s\r\n", atkey_str_buff);

  // send command and recv response
  const size_t recvlen = 4096;
  recv = calloc(recvlen, sizeof(unsigned char));
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t recv_olen = 0;

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, strlen((char *)command),
                                 recv, recvlen, &recv_olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  char *response = (char *)recv;
  short atsign_with_at_len = (short)strlen(atclient->atsign.atsign);

  // Truncate response: "@" + myatsign + "@"
  int response_prefix_len = atsign_with_at_len + 2;
  response_prefix = malloc(response_prefix_len * sizeof(char));
  snprintf(response_prefix, response_prefix_len, "@%s@", atclient->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvlen, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvlen, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // Truncate response : "data:"
  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {
    response = response + 5;

    unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
    const cJSON *root = cJSON_Parse(response);
    if (root == NULL) {
      ret = 1;
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
      goto exit;
    }

    cJSON *metadata = cJSON_GetObjectItem(root, "metaData");
    if (metadata == NULL) {
      ret = 1;
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
      goto exit;
    }

    char *metadatastr = cJSON_Print(metadata);

    ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr, strlen(metadatastr));
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
      goto exit;
    }

    // manage IV
    if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
      size_t ivolen;
      ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce.str, atkey->metadata.ivnonce.olen, iv,
                                  ATCHOPS_IV_BUFFER_SIZE, &ivolen);
      if (ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
        goto exit;
      }

      if (ivolen != ATCHOPS_IV_BUFFER_SIZE) {
        ret = 1;
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivolen != ivlen (%d != %d)\n", ivolen,
                              ATCHOPS_IV_BUFFER_SIZE);
        goto exit;
      }
    } else {
      // use legacy IV
      memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
    }

    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (data == NULL) {
      ret = 1;
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
      goto exit;
    }

    // decrypt response data
    ret = atchops_aesctr_decrypt(enc_key, (size_t)strlen(enc_key), ATCHOPS_AES_256, iv,
                                 (unsigned char *)data->valuestring, strlen(data->valuestring), (unsigned char *)value,
                                 valuelen, valueolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
      goto exit;
    }
  }

  ret = 0;
  goto exit;
exit : {
  if (enc_key_mem)
    free(enc_key);
  if (atkey_str_buff)
    free(atkey_str_buff);
  if (command)
    free(command);
  if (recv)
    free(recv);
  if (response_prefix)
    free(response_prefix);
  return ret;
}
}

static int atclient_get_sharedkey_shared_by_other_with_me(atclient *atclient, atclient_atkey *atkey, char *value,
                                                          const size_t valuelen, size_t *valueolen,
                                                          char *shared_enc_key) {
  int ret = 1;
  char *command = NULL;
  unsigned char *recv = NULL;
  char *response_prefix = NULL;

  char *enc_key = shared_enc_key;
  if (enc_key == NULL) {
    enc_key = malloc(45);
    atclient_atsign recipient;
    ret = atclient_atsign_init(&recipient, atkey->sharedby.str);
    if (ret != 0) {
      goto exit;
    }
    ret = atclient_get_encryption_key_shared_by_other(atclient, &recipient, enc_key);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_encryption_key_shared_by_me: %d\n", ret);
      goto exit;
    }
  }

  char *namespace = "";
  size_t namespace_len = 0;
  short extra_point_len = 0; // "." before namespace

  if (atkey->namespacestr.str != NULL && atkey->namespacestr.str[0] != '\0') {
    namespace = atkey->namespacestr.str;
    namespace_len = atkey->namespacestr.olen;
    extra_point_len = 1;
  }

  // build command
  // command_prefix = "lookup:"
  const short command_prefix_len = 11;
  const size_t command_len =
      command_prefix_len + atkey->name.olen + extra_point_len + namespace_len + atkey->sharedby.olen + 3;
  command = calloc(command_len, sizeof(char));
  snprintf(command, command_len, "lookup:all:%s%s%s%s\r\n", atkey->name.str, extra_point_len ? "." : "", namespace,
           atkey->sharedby.str);

  // send command and recv response
  const size_t recvlen = 4096;
  recv = calloc(recvlen, sizeof(unsigned char));
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t recv_olen = 0;

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)command, strlen((char *)command),
                                 recv, recvlen, &recv_olen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  char *response = (char *)recv;
  short atsign_with_at_len = (short)strlen(atclient->atsign.atsign);

  // Truncate response: "@" + myatsign + "@"
  int response_prefix_len = atsign_with_at_len + 2;
  response_prefix = malloc(response_prefix_len * sizeof(char));
  snprintf(response_prefix, response_prefix_len, "@%s@", atclient->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvlen, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvlen, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // Truncate response : "data:"
  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {
    response = response + 5;

    unsigned char iv[ATCHOPS_IV_BUFFER_SIZE];
    const cJSON *root = cJSON_Parse(response);
    if (root == NULL) {
      ret = 1;
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_Parse: %d\n", ret);
      goto exit;
    }

    cJSON *metadata = cJSON_GetObjectItem(root, "metaData");
    if (metadata == NULL) {
      ret = 1;
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
      goto exit;
    }

    char *metadatastr = cJSON_Print(metadata);

    ret = atclient_atkey_metadata_from_jsonstr(&(atkey->metadata), metadatastr, strlen(metadatastr));
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_metadata_from_jsonstr: %d\n", ret);
      goto exit;
    }

    // manage IV
    if (atclient_atkey_metadata_is_ivnonce_initialized(&atkey->metadata)) {
      size_t ivolen;
      ret = atchops_base64_decode((unsigned char *)atkey->metadata.ivnonce.str, atkey->metadata.ivnonce.olen, iv,
                                  ATCHOPS_IV_BUFFER_SIZE, &ivolen);
      if (ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_base64_decode: %d\n", ret);
        goto exit;
      }

      if (ivolen != ATCHOPS_IV_BUFFER_SIZE) {
        ret = 1;
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ivolen != ivlen (%d != %d)\n", ivolen,
                              ATCHOPS_IV_BUFFER_SIZE);
        goto exit;
      }
    } else {
      // use legacy IV
      memset(iv, 0, sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
    }

    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (data == NULL) {
      ret = 1;
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "cJSON_GetObjectItem: %d\n", ret);
      goto exit;
    }

    // decrypt response data
    ret = atchops_aesctr_decrypt(enc_key, (size_t)strlen(enc_key), ATCHOPS_AES_256, iv,
                                 (unsigned char *)data->valuestring, strlen(data->valuestring), (unsigned char *)value,
                                 valuelen, valueolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_aesctr_decrypt: %d\n", ret);
      goto exit;
    }
  }

  ret = 0;
  goto exit;
exit : {
  if (command)
    free(command);
  if (recv)
    free(recv);
  if (response_prefix)
    free(response_prefix);
  return ret;
}
}

int atclient_delete(atclient *atclient, const atclient_atkey *atkey) {
  int ret = 1;

  atclient_atstr cmdbuffer;
  atclient_atstr_init_literal(&cmdbuffer, ATCLIENT_ATKEY_FULL_LEN + strlen("delete:"), "delete:");

  char atkeystr[ATCLIENT_ATKEY_FULL_LEN];
  memset(atkeystr, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN);
  size_t atkeystrolen = 0;

  unsigned char recv[4096] = {0};
  size_t recvolen = 0;

  ret = atclient_atkey_to_string(atkey, atkeystr, ATCLIENT_ATKEY_FULL_LEN, &atkeystrolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string: %d\n", ret);
    goto exit;
  }

  ret = atclient_atstr_append(&cmdbuffer, "%.*s\n", (int)atkeystrolen, atkeystr);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_append: %d\n", ret);
    goto exit;
  }

  ret = atclient_connection_send(&(atclient->secondary_connection), (unsigned char *)cmdbuffer.str, cmdbuffer.olen,
                                 recv, 4096, &recvolen);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_connection_send: %d\n", ret);
    goto exit;
  }

  if (!atclient_stringutils_starts_with((char *)recv, recvolen, "data:", 5)) {
    ret = 1;
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "recv was \"%.*s\" and did not have prefix \"data:\"\n",
                          (int)recvolen, recv);
    goto exit;
  }

  ret = 0;
  goto exit;
exit : {
  atclient_atstr_free(&cmdbuffer);
  return ret;
}
}

int atclient_get_encryption_key_shared_by_me(atclient *ctx, const atclient_atsign *recipient,
                                             char *enc_key_shared_by_me, bool create_new_if_not_found) {
  int ret = 1;

  // llookup:shared_key.recipient_atsign@myatsign
  char *command_prefix = "llookup:shared_key.";
  const short command_prefix_len = 19;
  short atsign_with_at_len = (short)strlen(ctx->atsign.atsign);

  short command_len = command_prefix_len + (short)strlen(recipient->without_prefix_str) + atsign_with_at_len + 3;
  char command[command_len];
  snprintf(command, command_len, "llookup:shared_key.%s%s\r\n", recipient->without_prefix_str, ctx->atsign.atsign);

  const size_t recvlen = 1024;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t olen = 0;

  ret = atclient_connection_send(&(ctx->secondary_connection), (unsigned char *)command, strlen((char *)command), recv,
                                 recvlen, &olen);
  if (ret != 0) {
    return ret;
  }

  char *response = (char *)recv;

  // Truncate response: "@" + myatsign + "@"
  int response_prefix_len = atsign_with_at_len + 2;
  char response_prefix[response_prefix_len];
  snprintf(response_prefix, response_prefix_len, "@%s@", ctx->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvlen, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvlen, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // does my atSign already have the recipient's shared key?
  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {
    response = response + 5;

    // 44 + 1
    const size_t plaintextlen = 45;
    unsigned char plaintext[plaintextlen];
    memset(plaintext, 0, plaintextlen);
    size_t plaintextolen = 0;

    ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, (const unsigned char *)response, strlen((char *)response),
                              plaintext, plaintextlen, &plaintextolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
      return ret;
    }
    memcpy(enc_key_shared_by_me, plaintext, plaintextlen);
  }

  else if (atclient_stringutils_starts_with((char *)recv, recvlen, "error:AT0015-key not found",
                                            strlen("error:AT0015-key not found"))) {
    // or do I need to create, store and share a new shared key?
    if (create_new_if_not_found) {
      // TODO: instead return a specific signal indiciating key not found and let the developer create their own key
      // ret = atclient_create_shared_encryption_key(ctx, root_conn, recipient, enc_key_shared_by_me);
      if (ret != 0) {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_create_shared_encryption_key: %d\n", ret);
        return ret;
      }
    } else {
      ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
      return ret;
    }
  }

  return 0;
}

int atclient_get_encryption_key_shared_by_other(atclient *ctx, const atclient_atsign *recipient,
                                                char *enc_key_shared_by_other) {
  int ret = 1;

  // llookup:cached:@myatsign:shared_key@recipient_atsign
  // lookup:shared_key@recipient_atsign
  char *command_prefix = "lookup:shared_key@";
  const short command_prefix_len = 18;

  short command_len = command_prefix_len + strlen(recipient->without_prefix_str) + 3;
  char command[command_len];
  snprintf(command, command_len, "lookup:shared_key@%s\r\n", recipient->without_prefix_str);

  const size_t recvlen = 1024;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t olen = 0;

  ret = atclient_connection_send(&(ctx->secondary_connection), (unsigned char *)command, strlen((char *)command), recv,
                                 recvlen, &olen);
  if (ret != 0) {
    return ret;
  }

  char *response = (char *)recv;

  // Truncate response: "@" + myatsign + "@"
  short response_prefix_len = (short)strlen(ctx->atsign.without_prefix_str) + 3;
  char response_prefix[response_prefix_len];
  snprintf(response_prefix, response_prefix_len, "@%s@", ctx->atsign.without_prefix_str);

  if (atclient_stringutils_starts_with(response, recvlen, response_prefix, response_prefix_len)) {
    response = response + response_prefix_len;
  }

  if (atclient_stringutils_ends_with(response, recvlen, response_prefix, response_prefix_len)) {
    response[strlen(response) - response_prefix_len - 1] = '\0';
  }

  // does my atSign already have the recipient's shared key?
  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {

    response = response + 5;

    // 44 + 1
    const size_t plaintextlen = 45;
    unsigned char plaintext[plaintextlen];
    memset(plaintext, 0, plaintextlen);
    size_t plaintextolen = 0;

    ret = atchops_rsa_decrypt(ctx->atkeys.encryptprivatekey, (const unsigned char *)response, strlen((char *)response),
                              plaintext, plaintextlen, &plaintextolen);
    if (ret != 0) {
      atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d\n", ret);
      return ret;
    }
    memcpy(enc_key_shared_by_other, plaintext, plaintextlen);
  } else if (atclient_stringutils_starts_with((char *)recv, recvlen, "error:AT0015-key not found",
                                              strlen("error:AT0015-key not found"))) {
    // There is nothing we can do, except wait for the recipient to share a new key
    // We want to mark this situation with a easily distinguishable return value
    ret = ATCLIENT_ERR_AT0015_KEY_NOT_FOUND;
    return ret;
  }
  return 0;
}

int atclient_create_shared_encryption_key(atclient *ctx, atclient_connection *root_conn,
                                          const atclient_atsign *recipient, char *enc_key_shared_by_me) {
  int ret = 1;

  // get client and recipient public encryption keys
  const size_t bufferlen = 1024;
  char client_public_encryption_key[bufferlen];
  char recipient_public_encryption_key[bufferlen];
  ret = atclient_get_public_encryption_key(ctx, root_conn, NULL, client_public_encryption_key);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_public_encryption_key: %d\n", ret);
    return ret;
  }
  ret = atclient_get_public_encryption_key(ctx, root_conn, recipient, recipient_public_encryption_key);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get_public_encryption_key: %d\n", ret);
    return ret;
  }

  // generate a new aes key
  const size_t keybase64len = 45;
  unsigned char new_shared_encryption_key_b64[keybase64len];
  memset(new_shared_encryption_key_b64, 0, keybase64len);
  size_t keybase64olen = 0;
  ret = atchops_aes_generate_keybase64(new_shared_encryption_key_b64, keybase64len, &keybase64olen, ATCHOPS_AES_256);
  if (ret != 0) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR,
                          "atchops_aes_generate_keybase64: %d\n; Error generating key: keybase64: %.*s\n", ret,
                          (int)keybase64olen, new_shared_encryption_key_b64);
    return ret;
  }

  const size_t ciphertextlen = 1024;
  size_t ciphertextolen = 0;

  // encrypt new shared key with client's public key
  atchops_rsakey_publickey client_publickey;
  atchops_rsakey_publickey_init(&client_publickey);

  ret = atchops_rsakey_populate_publickey(&client_publickey, client_public_encryption_key,
                                          strlen(client_public_encryption_key));
  if (ret != 0) {
    printf("atchops_rsakey_populate_publickey (failed): %d\n", ret);
    return ret;
  }

  unsigned char new_shared_encryption_key_b64_encrypted_with_client_public_key_b64[ciphertextlen];
  memset(new_shared_encryption_key_b64_encrypted_with_client_public_key_b64, 0, ciphertextlen);

  ret = atchops_rsa_encrypt(client_publickey, (const unsigned char *)new_shared_encryption_key_b64, keybase64len,
                            new_shared_encryption_key_b64_encrypted_with_client_public_key_b64, ciphertextlen,
                            &ciphertextolen);
  if (ret != 0) {
    printf("atchops_rsa_encrypt (failed): %d\n", ret);
    return ret;
  }

  // encrypt new shared key with recipient's public key
  atchops_rsakey_publickey recipient_publickey;
  atchops_rsakey_publickey_init(&recipient_publickey);

  ret = atchops_rsakey_populate_publickey(&recipient_publickey, recipient_public_encryption_key,
                                          strlen(recipient_public_encryption_key));
  if (ret != 0) {
    printf("atchops_rsakey_populate_publickey (failed): %d\n", ret);
    return ret;
  }

  unsigned char new_shared_encryption_key_b64_encrypted_with_recipient_public_key_b64[ciphertextlen];
  memset(new_shared_encryption_key_b64_encrypted_with_recipient_public_key_b64, 0, ciphertextlen);

  ret = atchops_rsa_encrypt(recipient_publickey, (const unsigned char *)new_shared_encryption_key_b64, keybase64len,
                            new_shared_encryption_key_b64_encrypted_with_recipient_public_key_b64, ciphertextlen,
                            &ciphertextolen);
  if (ret != 0) {
    printf("atchops_rsa_encrypt (failed): %d\n", ret);
    return ret;
  }

  short client_with_at_len = (short)strlen(ctx->atsign.atsign);
  short recipient_without_at_len = (short)strlen(recipient->without_prefix_str);

  // save encrypted key for us
  // update:shared_key.recipient@client key\r\n\0
  char *command1_prefix = "update:shared_key.";
  const short command1_prefix_len = 18;

  short command1_len = command1_prefix_len + recipient_without_at_len + client_with_at_len +
                       strlen((char *)new_shared_encryption_key_b64_encrypted_with_client_public_key_b64) + 4;
  char command1[command1_len];
  snprintf(command1, command1_len, "update:shared_key.%s%s %s\r\n", recipient->without_prefix_str, ctx->atsign.atsign,
           new_shared_encryption_key_b64_encrypted_with_client_public_key_b64);

  // save encrypted key for them
  // ttr = 3888000 (45 days)
  // update:ttr:3888000:recipient:shared_key@client key\r\n\0
  char *command2_prefix = "update:ttr:3888000:";
  const short command2_prefix_len = 19;

  short command2_len = command2_prefix_len + recipient_without_at_len + client_with_at_len +
                       strlen((char *)new_shared_encryption_key_b64_encrypted_with_recipient_public_key_b64) + 5;
  char command2[command2_len];
  snprintf(command2, command2_len, "update:ttr:3888000:%s:shared_key%s %s\r\n", recipient->without_prefix_str,
           ctx->atsign.atsign, new_shared_encryption_key_b64_encrypted_with_recipient_public_key_b64);

  // copy new aes key to func parameter
  memcpy(enc_key_shared_by_me, new_shared_encryption_key_b64, 45);

  return 0;
}

int atclient_get_public_encryption_key(atclient *ctx, atclient_connection *root_conn, const atclient_atsign *atsign,
                                       char *public_encryption_key) {

  int ret = 1;

  // plookup:publickey@atsign
  char *command_prefix = "plookup:publickey";
  const short command_prefix_len = 17;

  const atclient_atsign *pub_enc_key_atsign = atsign != NULL ? atsign : &ctx->atsign;
  short command_len = command_prefix_len + strlen(pub_enc_key_atsign->atsign) + 3;
  char command[command_len];
  snprintf(command, command_len, "plookup:publickey%s\r\n", pub_enc_key_atsign->atsign);

  // execute command
  const size_t recvlen = 1024;
  unsigned char recv[recvlen];
  memset(recv, 0, sizeof(unsigned char) * recvlen);
  size_t olen = 0;

  ret = atclient_connection_send(&(ctx->secondary_connection), (unsigned char *)command, strlen((char *)command), recv,
                                 recvlen, &olen);
  if (ret != 0) {
    return ret;
  }

  char *response = (char *)recv;

  if (atclient_stringutils_starts_with(response, recvlen, "data:", 5)) {
    response = response + 5;
    memcpy(public_encryption_key, response, 1024);
  } else if (atclient_stringutils_starts_with((char *)recv, recvlen, "error:AT0015-key not found",
                                              strlen("error:AT0015-key not found"))) {
    atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atchops_rsa_decrypt: %d; error:AT0015-key not found\n",
                          ret);
    ret = 1;
    return ret;
  }

  return 0;
}

void atclient_free(atclient *ctx) { atclient_connection_free(&(ctx->secondary_connection)); }
