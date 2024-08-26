#ifndef ATCLIENT_CONNECTION_HOOKS_H
#define ATCLIENT_CONNECTION_HOOKS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define VALUE_INITIALIZED 0b00000001

#define ATCLIENT_CONNECTION_HOOKS_PRE_READ_INDEX 0
#define ATCLIENT_CONNECTION_HOOKS_POST_READ_INDEX 0
#define ATCLIENT_CONNECTION_HOOKS_PRE_WRITE_INDEX 0
#define ATCLIENT_CONNECTION_HOOKS_POST_WRITE_INDEX 0

#define ATCLIENT_CONNECTION_HOOKS_PRE_READ_INITIALIZED (VALUE_INITIALIZED << 0)
#define ATCLIENT_CONNECTION_HOOKS_POST_READ_INITIALIZED (VALUE_INITIALIZED << 1)
#define ATCLIENT_CONNECTION_HOOKS_PRE_WRITE_INITIALIZED (VALUE_INITIALIZED << 2)
#define ATCLIENT_CONNECTION_HOOKS_POST_WRITE_INITIALIZED (VALUE_INITIALIZED << 3)

struct atclient_connection;

typedef struct atclient_connection_hook_params {
  unsigned char *src;
  size_t src_len;
  unsigned char *recv;
  size_t recv_size;
  size_t *recv_len;
} atclient_connection_hook_params;

typedef int atclient_connection_hook(atclient_connection_hook_params *params);

typedef enum atclient_connection_hook_type {
  ATCLIENT_CONNECTION_HOOK_TYPE_NONE = 0,
  ATCLIENT_CONNECTION_HOOK_TYPE_PRE_READ,
  ATCLIENT_CONNECTION_HOOK_TYPE_POST_READ,
  ATCLIENT_CONNECTION_HOOK_TYPE_PRE_WRITE,
  ATCLIENT_CONNECTION_HOOK_TYPE_POST_WRITE,
} atclient_connection_hook_type;

typedef struct atclient_connection_hooks {
  bool _is_nested_call;
  atclient_connection_hook *pre_read;
  atclient_connection_hook *post_read;
  atclient_connection_hook *pre_write;
  atclient_connection_hook *post_write;
  uint8_t _initialized_fields[1];
} atclient_connection_hooks;

bool atclient_connection_hooks_is_enabled(struct atclient_connection *ctx);
int atclient_connection_hooks_enable(struct atclient_connection *conn);
void atclient_connection_hooks_disable(struct atclient_connection *conn);

// Q. Why is hook a void pointer?
// A. In case we want to add future hook types which use a different function signature
int atclient_connection_hooks_set(struct atclient_connection *ctx, const atclient_connection_hook_type type, void *hook);

bool atclient_connection_hooks_is_pre_read_initialized(const struct atclient_connection *ctx);
bool atclient_connection_hooks_is_post_read_initialized(const struct atclient_connection *ctx);
bool atclient_connection_hooks_is_pre_write_initialized(const struct atclient_connection *ctx);
bool atclient_connection_hooks_is_post_write_initialized(const struct atclient_connection *ctx);


#endif