
#include "atchops/uuid.h"
#include <atlogger/atlogger.h>
#include <stddef.h>
#include <string.h>
#include <uuid4/uuid4.h>

#define TAG "uuid"

int atchops_uuid_init(void) { return uuid4_init(); }

int atchops_uuid_generate(char *uuidstr, const size_t uuidstrlen) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (uuidstr == NULL) {
    ret = 1; // UUID buffer is NULL
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "UUID buffer is NULL\n");
    goto exit;
  }

  if (uuidstrlen <= 0) {
    ret = 1; // UUID buffer length is less than or equal to 0
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "UUID buffer length is less than or equal to 0\n");
    goto exit;
  }

  if (uuidstrlen < 37) {
    ret = 1; // UUID string is 36 characters long + 1 for null terminator = 37 minimum buffer length
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "UUID buffer length is less than 37\n");
    goto exit;
  }

  /*
   * 2. Generate UUID
   */
  uuid4_generate(uuidstr);
  if (strlen(uuidstr) <= 0) {
    ret = 1; // an error occurred regarding the UUID generation and writing it to the buffer
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}
