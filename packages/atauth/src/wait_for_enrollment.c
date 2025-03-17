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

  int max_tries = 50;
  for (int i = 0; i < max_tries; i++) {
    // Silence logging during pkam auth to suppress error messages which we expect to occur until enrollment is approved
    enum atlogger_logging_level logging_level = atlogger_get_logging_level();
    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_NONE);
    ret = atclient_pkam_authenticate(ctx, atsign, atkeys, (atclient_authenticate_options *)opts, &err_msg);
    atlogger_set_logging_level(logging_level);

    if (ret == 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "enrollment approved | APKAM auth success\n");
      return ret;
    }

    if (err_msg != NULL && is_enrollment_denied(err_msg)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "enrollment id: %s has been denied\n", atkeys->enrollment_id);
      ret = 1;
      return ret;
    }

    if (err_msg != NULL && is_enrollment_pending(err_msg)) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_WARN, "enrollment not approved yet | Retrying in %d secs\n",
                   ATAUTH_DEFAULT_APKAM_RETRY_INTERVAL);
      sleep(ATAUTH_DEFAULT_APKAM_RETRY_INTERVAL);
      continue;
    }

    if (err_msg != NULL) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Unexpected error: \n%s\n", err_msg);
    } else {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "An unknown error occurred, please contact support.\n");
    }
    return 2;
  }

  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Enrollment not completed within %d attempts, exiting\n", max_tries);
  return 3;
}

int is_enrollment_denied(const char *err_msg) {
  return strncmp(err_msg, ATAUTH_ENROLLMENT_DENIED_ERR_CODE, strlen(ATAUTH_ENROLLMENT_DENIED_ERR_CODE)) == 0;
}

int is_enrollment_pending(const char *err_msg) {
  return strncmp(err_msg, ATAUTH_ENROLLMENT_PENDING_ERR_CODE, strlen(ATAUTH_ENROLLMENT_PENDING_ERR_CODE)) == 0;
}
