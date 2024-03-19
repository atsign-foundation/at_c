
#include "atchops/uuid.h"
#include <string.h>
#include <uuid4/uuid4.h>
#include <stddef.h>

int atchops_uuid_init(void) { return uuid4_init(); }

int atchops_uuid_generate(char *uuidstr, const size_t uuidstrlen) {
  int ret;
  if (uuidstrlen < 37) {
    ret = 1; // UUID string is 36 characters long + 1 for null terminator = 37 minimum buffer length
    goto exit;
  }
  uuid4_generate(uuidstr);
  if (strlen(uuidstr) <= 0) {
    ret = 1; // an error occurred regarding the UUID generation and writing it to the buffer
    goto exit;
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}
