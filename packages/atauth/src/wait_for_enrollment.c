#include "wait_for_enrollment.h"
#include "atclient/atclient.h"
#include "atlogger/atlogger.h"
#include "constants.h"
#include <string.h>
#include <unistd.h>

#define TAG "atauth_wait_for_enrollment"

int wait_for_enrollment(atclient *ctx, const char *atsign, const atclient_atkeys *atkeys,
                        const atclient_authenticate_options *opts) {
  int ret = 1;
  char *err_msg;

  while (true) {
    ret = atclient_pkam_authenticate(ctx, atsign, atkeys, (atclient_authenticate_options *)opts, &err_msg);

    if (ret == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "enrollment approved | APKAM auth success\n");
      return ret;
    }

    if (err_msg != NULL && is_enrollment_denied(err_msg)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "enrollment id: %s has been denied\n", atkeys->enrollment_id);
      ret = 1;
      return ret;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN, "enrollment not approved yet | Retrying in %d secs\n",
                 ATAUTH_DEFAULT_APKAM_RETRY_INTERVAL);
    sleep(ATAUTH_DEFAULT_APKAM_RETRY_INTERVAL);
  }
}

int is_enrollment_denied(const char *err_msg) {
  return strncmp(err_msg, ATAUTH_ENROLLMENT_DENIED_ERR_CODE, strlen(ATAUTH_ENROLLMENT_DENIED_ERR_CODE)) == 0;
}
