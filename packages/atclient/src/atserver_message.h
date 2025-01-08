#ifndef ATSERVER_MESSAGE_H
#define ATSERVER_MESSAGE_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

struct atserver_message {
  char *buffer;
  // metadata about buffer
  // len: length of the buffer
  // prompt: is `@` || `@<atsign>@` portion
  // token: is `data:` || `error:` || `notification:`
  // body: is the rest of the response contents

  const uint16_t len;
  // prompt offset is derived as 0 if prompt_len > 0
  const uint8_t prompt_len;
  // token offset = prompt_len
  const uint8_t token_len;
  // body offset = prompt_len + token_len
  // body_len = len - prompt_len - token_len
};

uint16_t atserver_message_get_body_len(struct atserver_message message);

const char *atserver_message_get_prompt(struct atserver_message message);
const char *atserver_message_get_token(struct atserver_message message);
char *atserver_message_get_body(struct atserver_message message);

struct atserver_message atserver_message_parse(char *buffer, uint16_t len);
void atserver_message_free(struct atserver_message *message);

#ifdef __cplusplus
}
#endif

#endif
