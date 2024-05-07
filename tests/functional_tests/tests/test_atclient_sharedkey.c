#include "functional_tests/config.h"
#include "functional_tests/helpers.h"
#include <atclient/atclient.h>
#include <atclient/constants.h>
#include <atlogger/atlogger.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "test_atclient_sharedkey"

#define ATKEY_KEY "test_atclient_sharedkey"
#define ATKEY_NAMESPACE "functional_tests"
#define ATKEY_SHAREDBY FIRST_ATSIGN
#define ATKEY_SHAREDWITH SECOND_ATSIGN
#define ATKEY_VALUE "Hello World!!!! 123 :D"
#define ATKEY_TTL 60 * 1000 * 5 // 5 minutes
#define ATKEY_TTR -1            // DO NOT CACHE

static int test_1_put(atclient *atclient);
static int test_2_get_as_sharedby(atclient *atclient);
static int test_3_get_as_sharedwith(atclient *atclient);
static int test_4_delete(atclient *atclient);
static int test_5_should_not_exist_as_sharedby(atclient *atclient);
static int tear_down_sharedenckeys(atclient *atclient);

int main() {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  char *atsign1 = FIRST_ATSIGN;
  const size_t atsign1len = strlen(atsign1);

  char *atsign2 = SECOND_ATSIGN;
  const size_t atsign2len = strlen(atsign2);

  atclient atclient1;
  atclient_init(&atclient1);

  // atclient atclient2;
  // atclient_init(&atclient2);

  if ((ret = functional_tests_pkam_auth(&atclient1, atsign1)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_up: %d\n", ret);
    goto exit;
  }

  if ((ret = test_1_put(&atclient1)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_1_put: %d\n", ret);
    goto exit;
  }

  if ((ret = test_2_get_as_sharedby(&atclient1)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_2_get_as_sharedby: %d\n", ret);
    goto exit;
  }

  // if((ret = functional_tests_pkam_auth(&atclient2, atsign2)) != 0)
  // {
  //     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "set_up: %d\n", ret);
  //     goto exit;
  // }

  // if((ret = test_3_get_as_sharedwith(&atclient2)) != 0)
  // {
  //     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_3_get_as_sharedwith: %d\n", ret);
  //     goto exit;
  // }

  // if((ret = test_4_delete(&atclient1)) != 0)
  // {
  //     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_4_delete: %d\n", ret);
  //     goto exit;
  // }

  // if((ret = test_5_should_not_exist_as_sharedby(&atclient1)) != 0)
  // {
  //     atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test_5_should_not_exist: %d\n", ret);
  //     goto exit;
  // }

  goto exit;

exit: {
  // if (tear_down_sharedenckeys(&atclient1) != 0) {
  //   atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "tear_down: %d\n", ret);
  //   ret = 1;
  // }
  atclient_free(&atclient1);
  // atclient_free(&atclient2);
  return ret;
}
}

static int test_1_put(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_put Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "creating sharedkey...\n");
  if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH),
                                             ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_sharedkey: %d\n", ret);
    goto exit;
  }

  atclient_atkey_metadata_set_ttl(&atkey.metadata, ATKEY_TTL);
  atclient_atkey_metadata_set_ttr(&atkey.metadata, ATKEY_TTR);

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "putting...\n");
  if ((ret = atclient_put(atclient, &atkey, ATKEY_VALUE, strlen(ATKEY_VALUE), NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_put: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "put done\n");

  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_1_put End (%d)\n", ret);
  return ret;
}
}

static int test_2_get_as_sharedby(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_get_as_sharedby Begin\n");


  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "creating sharedkey...\n");
  atclient_atkey atkey;
  atclient_atkey_init(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "created sharedkey\n");

  const size_t valuesize = 2048;
  char value[valuesize];
  memset(value, 0, sizeof(char) * valuesize);
  size_t valuelen = 0;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "creating sharedkey...\n");
  if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH),
                                             ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_sharedkey: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "getting...\n");
  if ((ret = atclient_get_sharedkey(atclient, &atkey, value, valuesize, &valuelen, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value: \"%s\"\n", value);

  if ((ret = strcmp(value, ATKEY_VALUE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value mismatch\n");
    goto exit;
  }

  // check ttl, should be 5 minutes
  if (!atclient_atkey_metadata_is_ttl_initialized(&(atkey.metadata))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ttl not initialized\n");
    ret = 1;
    goto exit;
  } else if (atkey.metadata.ttl != ATKEY_TTL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ttl mismatch. Expected %ld, got %ld\n", ATKEY_TTL,
                 atkey.metadata.ttl);
    ret = 1;
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "ttl matched: %ld\n", atkey.metadata.ttl);

  // check ttr, should be -1
  if (!atclient_atkey_metadata_is_ttr_initialized(&(atkey.metadata))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ttr not initialized\n");
    ret = 1;
    goto exit;
  } else if (atkey.metadata.ttr != ATKEY_TTR) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ttr mismatch. Expected %ld, got %ld\n", ATKEY_TTR,
                 atkey.metadata.ttr);
    ret = 1;
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "ttr matched: %ld\n", atkey.metadata.ttr);

  ret = 0;
  goto exit;
exit: {
  // print all metadata in atkey
  // print all initialized fields as integers
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.initializedfields[0]: %d\n", atkey.metadata.initializedfields[0]);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.initializedfields[1]: %d\n", atkey.metadata.initializedfields[1]);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.initializedfields[2]: %d\n", atkey.metadata.initializedfields[2]);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.initializedfields[3]: %d\n", atkey.metadata.initializedfields[3]);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.createdby: %s\n", atkey.metadata.createdby.atsign);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.updatedby: %s\n", atkey.metadata.updatedby.atsign);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.status: %s\n", atkey.metadata.status.str);
  // version
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.version: %d\n", atkey.metadata.version);
  // expiresat
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.expiresat: %s\n", atkey.metadata.expiresat.str);
  // availableat
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.availableat: %s\n", atkey.metadata.availableat.str);
  // refreshat
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.refreshat: %s\n", atkey.metadata.refreshat.str);
  // createdat
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.createdat: %s\n", atkey.metadata.createdat.str);
  // updatedat
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.updatedat: %s\n", atkey.metadata.updatedat.str);
  // ispublic
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.ispublic: %d\n", atkey.metadata.ispublic);
  // is hiddden
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.ishidden: %d\n", atkey.metadata.ishidden);
  // / is cached
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.iscached: %d\n", atkey.metadata.iscached);
  //ttl
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.ttl: %ld\n", atkey.metadata.ttl);
  //ttb
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.ttb: %ld\n", atkey.metadata.ttb);
  //ttr
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.ttr: %ld\n", atkey.metadata.ttr);
  //ccd
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.ccd: %d\n", atkey.metadata.ccd);
  // isbinary
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.isbinary: %d\n", atkey.metadata.isbinary);
  // isencrypted
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.isencrypted: %d\n", atkey.metadata.isencrypted);
  // datasignature
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.datasignature: %s\n", atkey.metadata.datasignature.str);
  // sharedkeystatus
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.sharedkeystatus: %d\n", atkey.metadata.sharedkeystatus.str);
  // sharedkeyenc
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.sharedkeyenc: %s\n", atkey.metadata.sharedkeyenc.str);
  // pubkeyhash
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.pubkeyhash: %s\n", atkey.metadata.pubkeyhash.str);
  // pubkeyalgo
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.pubkeyalgo: %s\n", atkey.metadata.pubkeyalgo.str);
  // encoding
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.encoding: %s\n", atkey.metadata.encoding.str);
  // enckeyname
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.enckeyname: %s\n", atkey.metadata.enckeyname.str);
  // encalgo
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.encalgo: %s\n", atkey.metadata.encalgo.str);
  // ivonce
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.ivonce: %s\n", atkey.metadata.ivnonce.str);
  // skeenckeyname
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.skeenckeyname: %s\n", atkey.metadata.skeenckeyname.str);
  //skeencalgo
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkey.metadata.skeencalgo: %s\n", atkey.metadata.skeencalgo.str);

  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_2_get_as_sharedby End (%d)\n", ret);
  return ret;
}
}

static int test_3_get_as_sharedwith(atclient *atclient2) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_get_as_sharedwith Begin\n");

  const size_t valuesize = 2048;
  char value[valuesize];
  memset(value, 0, sizeof(char) * valuesize);
  size_t valuelen = 0;

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH),
                                             ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_sharedkey: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_get_sharedkey(atclient2, &atkey, value, valuesize, &valuelen, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_get: %d\n", ret);
    goto exit;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value: \"%s\"\n", value);

  if ((ret = strcmp(value, ATKEY_VALUE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "value mismatch\n");
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "value matched: %s == %s\n", value, ATKEY_VALUE);

  if (atkey.metadata.ttl != ATKEY_TTL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ttl mismatch. Expected %d, got %d\n", ATKEY_TTL,
                 atkey.metadata.ttl);
    ret = 1;
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "ttl matched: %d\n", atkey.metadata.ttl);

  if (atkey.metadata.ttr != ATKEY_TTR) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "ttr mismatch. Expected %d, got %d\n", ATKEY_TTR,
                 atkey.metadata.ttr);
    ret = 1;
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "ttr matched: %d\n", atkey.metadata.ttr);

  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_3_get_as_sharedwith End (%d)\n", ret);
  return ret;
}
}

static int test_4_delete(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_delete Begin\n");

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  if ((ret = atclient_atkey_create_sharedkey(&atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATKEY_SHAREDBY,
                                             strlen(ATKEY_SHAREDBY), ATKEY_SHAREDWITH, strlen(ATKEY_SHAREDWITH),
                                             ATKEY_NAMESPACE, strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_sharedkey: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_delete(atclient, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
    goto exit;
  }

  goto exit;
exit: {
  atclient_atkey_free(&atkey);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_4_delete End (%d)\n", ret);
  return ret;
}
}

static int test_5_should_not_exist_as_sharedby(atclient *atclient) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_should_not_exist Begin\n");

  if ((ret = functional_tests_selfkey_exists(atclient, ATKEY_KEY, ATKEY_SHAREDBY, ATKEY_NAMESPACE)) != false) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "functional_tests_selfkey_exists is 0 but should be 1: %d\n", ret);
    goto exit;
  }

  ret = 0;
  goto exit;
exit: {
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "test_5_should_not_exist End (%d)\n", ret);
  return ret;
}
}

static int tear_down_sharedenckeys(atclient *atclient1) {
  int ret = 1;

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "tear_down Begin\n");

  char atkeystrtemp[ATCLIENT_ATKEY_FULL_LEN];

  atclient_atkey atkey;
  atclient_atkey_init(&atkey);

  atclient_atkey atkeyforme;
  atclient_atkey_init(&atkeyforme);

  atclient_atkey atkeyforthem;
  atclient_atkey_init(&atkeyforthem);

  if ((ret = atclient_atkey_create_sharedkey(
           &atkey, ATKEY_KEY, strlen(ATKEY_KEY), ATKEY_SHAREDBY, strlen(ATKEY_SHAREDBY), ATKEY_SHAREDWITH,
           strlen(ATKEY_SHAREDWITH), ATKEY_NAMESPACE, ATKEY_NAMESPACE == NULL ? 0 : strlen(ATKEY_NAMESPACE))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_create_sharedkey: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_delete(atclient1, &atkey)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "deleted main shared atkey\n");

  memset(atkeystrtemp, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN);
  snprintf(atkeystrtemp, ATCLIENT_ATKEY_FULL_LEN, "shared_key.%s%s", ATKEY_SHAREDWITH + 1, ATKEY_SHAREDBY);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkeystrtemp: \"%s\"\n", atkeystrtemp);
  if ((ret = atclient_atkey_from_string(&atkeyforme, atkeystrtemp, strlen(atkeystrtemp))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d\n", ret);
    goto exit;
  }

  memset(atkeystrtemp, 0, sizeof(char) * ATCLIENT_ATKEY_FULL_LEN);
  snprintf(atkeystrtemp, ATCLIENT_ATKEY_FULL_LEN, "%s:shared_key%s", ATKEY_SHAREDWITH, ATKEY_SHAREDBY);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "atkeystrtemp: \"%s\"\n", atkeystrtemp);
  if ((ret = atclient_atkey_from_string(&atkeyforthem, atkeystrtemp, strlen(atkeystrtemp))) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_from_string: %d\n", ret);
    goto exit;
  }

  if ((ret = atclient_delete(atclient1, &atkeyforme)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "deleted shared enc key for me\n");

  if ((ret = atclient_delete(atclient1, &atkeyforthem)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_delete: %d\n", ret);
    goto exit;
  }
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "deleted shared enc key for them\n");

  ret = 0;
  goto exit;

exit: {
  atclient_atkey_free(&atkey);
  atclient_atkey_free(&atkeyforme);
  atclient_atkey_free(&atkeyforthem);
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "tear_down End (%d)\n", ret);
  return ret;
}
}
