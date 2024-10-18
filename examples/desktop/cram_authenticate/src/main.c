#include <atclient/atclient.h>
#include <atlogger/atlogger.h>
#include <atchops/base64.h>
#include <stdio.h>
#include <string.h>

#define ROOT_HOST "root.atsign.org"
#define ROOT_PORT 64

//#define CRAM_SECRET "27ec6d2bd2c18cbb0f1a2aa2a12666a87c5bd4af4b89f591c37dc0fd75217909adf0950e0f3c2d87cf50de2891d70b94bdf079b671a34275d02bfc06a4c7b723"
//#define ATSIGN "@25distinctivethe"

#define CRAM_SECRET "66e026167a79cb7e9d190afe7b01b3fc4f31bc3866a08cdcec06d82a7296e9febcac5d4f4a081728fb0ec9d08f27d4f866bd6570f3fe20c65464ace76643becb"
#define ATSIGN "@disciplinarygemini"

#define TAG "cram_authenticate"

int main(int argc, char **argv) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);
 
  atclient_authenticate_options options;
  atclient_authenticate_options_init(&options);

  atclient atclient;
  atclient_init(&atclient);

  const char *atsign = ATSIGN;
  const char *cram_secret = &CRAM_SECRET[0];
  
  if ((ret = atclient_cram_authenticate(&atclient, ATSIGN, cram_secret, &options)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate\n");
    goto exit;
  } else {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Authenticated\n");
  }

exit: {
  atclient_free(&atclient);
  atclient_authenticate_options_free(&options);
  return ret;
}
}