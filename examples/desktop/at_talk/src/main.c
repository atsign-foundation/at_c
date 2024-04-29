#include <atclient/atclient.h>
#include <atclient/atkeysfile.h>
#include <atclient/atsign.h>
#include <atlogger/atlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

#define ATKEYSFILE_PATH "/home/realvarx/.atsign/keys/@arrogantcheetah_key.atKeys"
#define ATSIGN "@arrogantcheetah"
#define RECIPIENT "@secondaryjackal"

#define TAG "at_talk"

int main(int argc, char **argv) {
  int ret = 0;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);

  // Init atclient
  atclient atclient;
  atclient_init(&atclient);

  // Init myatsign: the atsign that you'd like to use as a client
  // and assign it to the atclient "atsign" parameter
  atclient_atsign myatsign;
  ret = atclient_atsign_init(&myatsign, ATSIGN);
  if (ret != 0) {
    atclient_free(&atclient);
    return ret;
  }
  atclient.atsign = myatsign;

  // Init atkeysfile and read keys
  atclient_atkeysfile atkeysfile;
  atclient_atkeysfile_init(&atkeysfile);
  ret = atclient_atkeysfile_read(&atkeysfile, ATKEYSFILE_PATH);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_file_read: %d\n", ret);
    atclient_free(&atclient);
    atclient_atkeysfile_free(&atkeysfile);
    return ret;
  }

  // Init atkeys and assign them to the atclient "atkeys" parameter
  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);
  ret = atclient_atkeys_populate_from_atkeysfile(&atkeys, atkeysfile);
  if (ret != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkeys_populate_from_atkeysfile: %d\n", ret);
    goto exit1;
  }

  // Root connection and pkam auth
  atclient_connection root_conn;
  atclient_connection_init(&root_conn);
  atclient_connection_connect(&root_conn, "root.atsign.org", 64);

  ret = atclient_pkam_authenticate(&atclient, &root_conn, &atkeys, ATSIGN);
  if (ret != 0) {
    goto exit2;
  }

  // Init recipient's atsign
  atclient_atsign recipient;
  ret = atclient_atsign_init(&recipient, RECIPIENT);
  if (ret != 0) {
    goto exit2;
  }

  // Init variables and get the encryption keys

  char *enc_key_shared_by_me = malloc(45);
  ret = atclient_get_shared_encryption_key_shared_by_me(&atclient, &recipient, enc_key_shared_by_me, true);
  if (ret != 0) {
    free(enc_key_shared_by_me);
    goto exit2;
  }

  char *enc_key_shared_by_other = malloc(45);
  ret = atclient_get_shared_encryption_key_shared_by_other(&atclient, &recipient, enc_key_shared_by_other);
  if (ret != 0) {
    free(enc_key_shared_by_me);
    free(enc_key_shared_by_other);
    goto exit2;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "enc_key_shared_by_me: %s\n", enc_key_shared_by_me);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "enc_key_shared_by_other: %s\n", enc_key_shared_by_other);

  return ret;

exit1 : {
  atclient_free(&atclient);
  atclient_atkeysfile_free(&atkeysfile);
  atclient_atkeys_free(&atkeys);
  return ret;
}
exit2 : {
  atclient_free(&atclient);
  atclient_atkeysfile_free(&atkeysfile);
  atclient_atkeys_free(&atkeys);
  atclient_connection_disconnect(&(atclient.secondary_connection));
  atclient_connection_free(&root_conn);
  return ret;
}
}