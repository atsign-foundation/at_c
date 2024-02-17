#include "atclient/metadata.h"
#include "atclient/constants.h"
#include <stdlib.h>
#include <string.h>

void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata) {
  memset(metadata, 0, sizeof(atclient_atkey_metadata));

  atclient_atstr_init(&(metadata->createdby), ATSIGN_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->updatedby), ATSIGN_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->createdat), DATE_STR_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->updatedat), DATE_STR_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->sharedkeyenc), GENERAL_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->pubkeycs), GENERAL_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->ivnonce), GENERAL_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->enckeyname), GENERAL_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->encalgo), GENERAL_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->skeenckeyname), GENERAL_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->skeencalgo), GENERAL_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->availableat), DATE_STR_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->expiresat), DATE_STR_BUFFER_LENGTH);
  atclient_atstr_init(&(metadata->refreshat), DATE_STR_BUFFER_LENGTH);
}

int atclient_atkey_metadata_from_string(atclient_atkey_metadata *metadata, const char *metadatastr,
                                        const unsigned long metadatastrlen) {
  return 1; // TODO: implement
}

int atclient_atkey_metadata_to_string(const atclient_atkey_metadata metadata, char *metadatastr,
                                      const unsigned long metadatastrlen, unsigned long *metadatastrolen) {
  return 1; // TODO: implement
}

void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata) {
  atclient_atstr_free(&(metadata->createdat));
  atclient_atstr_free(&(metadata->updatedat));
  atclient_atstr_free(&(metadata->sharedkeyenc));
  atclient_atstr_free(&(metadata->pubkeycs));
  atclient_atstr_free(&(metadata->ivnonce));
  atclient_atstr_free(&(metadata->enckeyname));
  atclient_atstr_free(&(metadata->encalgo));
  atclient_atstr_free(&(metadata->skeenckeyname));
  atclient_atstr_free(&(metadata->skeencalgo));
  atclient_atstr_free(&(metadata->availableat));
  atclient_atstr_free(&(metadata->expiresat));
  atclient_atstr_free(&(metadata->refreshat));
}