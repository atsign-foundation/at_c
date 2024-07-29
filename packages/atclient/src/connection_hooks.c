#include "atclient/connection.h"
#include <atlogger/atlogger.h>
#include <string.h>
#include <stdlib.h>
#include "atclient/connection_hooks.h"
#include <stddef.h>

#define TAG "connection_hooks"

static void atclient_connection_hooks_set_is_enabled(atclient_connection *ctx, const bool enabled);

static void atclient_connection_hooks_set_is_pre_read_initialized(atclient_connection *ctx, const bool initialized);
static int atclient_connection_hooks_set_pre_read(atclient_connection *ctx, atclient_connection_hook *hook);
static void atclient_connection_hooks_unset_pre_read(atclient_connection *ctx);

static void atclient_connection_hooks_set_is_post_read_initialized(atclient_connection *ctx, const bool initialized);
static int atclient_connection_hooks_set_post_read(atclient_connection *ctx, atclient_connection_hook *hook);
static void atclient_connection_hooks_unset_post_read(atclient_connection *ctx);

static void atclient_connection_hooks_set_is_pre_write_initialized(atclient_connection *ctx, const bool initialized);
static int atclient_connection_hooks_set_pre_write(atclient_connection *ctx, atclient_connection_hook *hook);
static void atclient_connection_hooks_unset_pre_write(atclient_connection *ctx);

static void atclient_connection_hooks_set_is_post_write_initialized(atclient_connection *ctx, const bool initialized);
static int atclient_connection_hooks_set_post_write(atclient_connection *ctx, atclient_connection_hook *hook);
static void atclient_connection_hooks_unset_post_write(atclient_connection *ctx);

bool atclient_connection_hooks_is_enabled(atclient_connection *ctx) {
  if (ctx->hooks == NULL) {
    return false;
  }
  return ctx->_is_hooks_enabled;
}

int atclient_connection_hooks_enable(atclient_connection *conn) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (conn == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is NULL\n");
    return ret;
  }

  /*
   * 2. Disable hooks if they are already enabled
   */
  if (atclient_connection_hooks_is_enabled(conn)) {
    atclient_connection_hooks_disable(conn);
  }

  /*
   * 3. Allocate memory for the hooks struct
   */
  if ((conn->hooks = malloc(sizeof(atclient_connection_hooks))) == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for connection hooks\n");
    goto exit;
  }
  memset(conn->hooks, 0, sizeof(atclient_connection_hooks));
  atclient_connection_hooks_set_is_enabled(conn, true);

  /*
   * 4. Set any defaults
   */
  conn->hooks->readonly_src = true;

  ret = 0;
  goto exit;
exit: { return ret; }
}

void atclient_connection_hooks_disable(atclient_connection *conn) {
  /*
   * 1. Validate arguments
   */
  if (conn == NULL) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is NULL\n");
    return;
  }

  /*
   * 2. Free the hooks struct
   */
  if (atclient_connection_hooks_is_enabled(conn)) {
    free(conn->hooks);
  }
  atclient_connection_hooks_set_is_enabled(conn, false);
  conn->hooks = NULL;
}

int atclient_connection_hooks_set(atclient_connection *ctx, const atclient_connection_hook_type type, void *hook) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is NULL\n");
    return ret;
  }

  if (type == ATCLIENT_CONNECTION_HOOK_TYPE_NONE) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Received 'NONE' hook as hook set input type\n");
    return ret;
  }

  if (hook == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Hook is NULL\n");
    return ret;
  }

  if (!atclient_connection_hooks_is_enabled(ctx)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Make sure to enable hooks struct before trying to set a hook\n");
    return ret;
  }

  /*
   * 2. Set the hook
   */
  switch (type) {
  case ATCLIENT_CONNECTION_HOOK_TYPE_NONE:
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Received 'NONE' hook as hook set input type\n");
    goto exit;
  case ATCLIENT_CONNECTION_HOOK_TYPE_PRE_READ: {
    if((ret = atclient_connection_hooks_set_pre_read(ctx, (atclient_connection_hook *)hook)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set pre read hook\n");
      goto exit;
    }
    break;
  }
  case ATCLIENT_CONNECTION_HOOK_TYPE_POST_READ: {
    if((ret = atclient_connection_hooks_set_post_read(ctx, (atclient_connection_hook *)hook)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set post read hook\n");
      goto exit;
    }
    break;
  }
  case ATCLIENT_CONNECTION_HOOK_TYPE_PRE_WRITE: {
    if((ret = atclient_connection_hooks_set_pre_write(ctx, (atclient_connection_hook *)hook)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set pre write hook\n");
      goto exit;
    }
    break;
  }
  case ATCLIENT_CONNECTION_HOOK_TYPE_POST_WRITE: {
    if((ret = atclient_connection_hooks_set_post_write(ctx, (atclient_connection_hook *)hook)) != 0) {
      atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to set post write hook\n");
      goto exit;
    }
    break;
  }
  }

  ret = 0;
  goto exit;
exit: { return ret; }
}

bool atclient_connection_hooks_is_pre_read_initialized(const atclient_connection *ctx) {
  return ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_PRE_READ_INDEX] &
         ATCLIENT_CONNECTION_HOOKS_PRE_READ_INITIALIZED;
}

bool atclient_connection_hooks_is_post_read_initialized(const atclient_connection *ctx) {
  return ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_POST_READ_INDEX] &
         ATCLIENT_CONNECTION_HOOKS_POST_READ_INITIALIZED;
}

bool atclient_connection_hooks_is_pre_write_initialized(const atclient_connection *ctx) {
  return ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_PRE_WRITE_INDEX] &
         ATCLIENT_CONNECTION_HOOKS_PRE_WRITE_INITIALIZED;
}

bool atclient_connection_hooks_is_post_write_initialized(const atclient_connection *ctx) {
  return ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_POST_WRITE_INDEX] &
         ATCLIENT_CONNECTION_HOOKS_POST_WRITE_INITIALIZED;
}

static void atclient_connection_hooks_set_is_enabled(atclient_connection *ctx, const bool enabled) {
  ctx->_is_hooks_enabled = enabled;
}

static void atclient_connection_hooks_set_is_pre_read_initialized(atclient_connection *ctx, const bool initialized) {
  if (initialized) {
    ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_PRE_READ_INDEX] |=
        ATCLIENT_CONNECTION_HOOKS_PRE_READ_INITIALIZED;
  } else {
    ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_PRE_READ_INDEX] &=
        ~ATCLIENT_CONNECTION_HOOKS_PRE_READ_INITIALIZED;
  }
}

static int atclient_connection_hooks_set_pre_read(atclient_connection *ctx, atclient_connection_hook *hook) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is NULL\n");
    return ret;
  }

  if (!atclient_connection_hooks_is_enabled(ctx)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Make sure to enable hooks struct before trying to set a hook\n");
    return ret;
  }

  if (hook == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Hook is NULL\n");
    return ret;
  }

  if (atclient_connection_hooks_is_pre_read_initialized(ctx)) {
    atclient_connection_hooks_unset_pre_read(ctx);
  }

  ctx->hooks->pre_read = hook;
  atclient_connection_hooks_set_is_pre_read_initialized(ctx, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static void atclient_connection_hooks_unset_pre_read(atclient_connection *ctx) {
  ctx->hooks->pre_read = NULL;
  atclient_connection_hooks_set_is_pre_read_initialized(ctx, false);
}

static void atclient_connection_hooks_set_is_post_read_initialized(atclient_connection *ctx, const bool initialized) {
  if (initialized) {
    ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_POST_READ_INDEX] |=
        ATCLIENT_CONNECTION_HOOKS_POST_READ_INITIALIZED;
  } else {
    ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_POST_READ_INDEX] &=
        ~ATCLIENT_CONNECTION_HOOKS_POST_READ_INITIALIZED;
  }
}

static int atclient_connection_hooks_set_post_read(atclient_connection *ctx, atclient_connection_hook *hook) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is NULL\n");
    return ret;
  }

  if (!atclient_connection_hooks_is_enabled(ctx)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Make sure to enable hooks struct before trying to set a hook\n");
    return ret;
  }

  if (hook == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Hook is NULL\n");
    return ret;
  }

  if (atclient_connection_hooks_is_post_read_initialized(ctx)) {
    atclient_connection_hooks_unset_post_read(ctx);
  }

  ctx->hooks->post_read = hook;
  atclient_connection_hooks_set_is_post_read_initialized(ctx, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static void atclient_connection_hooks_unset_post_read(atclient_connection *ctx) {
  ctx->hooks->post_read = NULL;
  atclient_connection_hooks_set_is_post_read_initialized(ctx, false);
}

static void atclient_connection_hooks_set_is_pre_write_initialized(atclient_connection *ctx, const bool initialized) {
  if (initialized) {
    ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_PRE_WRITE_INDEX] |=
        ATCLIENT_CONNECTION_HOOKS_PRE_WRITE_INITIALIZED;
  } else {
    ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_PRE_WRITE_INDEX] &=
        ~ATCLIENT_CONNECTION_HOOKS_PRE_WRITE_INITIALIZED;
  }
}

static int atclient_connection_hooks_set_pre_write(atclient_connection *ctx, atclient_connection_hook *hook) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is NULL\n");
    return ret;
  }

  if (!atclient_connection_hooks_is_enabled(ctx)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Make sure to enable hooks struct before trying to set a hook\n");
    return ret;
  }

  if (hook == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Hook is NULL\n");
    return ret;
  }

  if (atclient_connection_hooks_is_pre_write_initialized(ctx)) {
    atclient_connection_hooks_unset_pre_write(ctx);
  }

  ctx->hooks->pre_write = hook;
  atclient_connection_hooks_set_is_pre_write_initialized(ctx, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static void atclient_connection_hooks_unset_pre_write(atclient_connection *ctx) {
  ctx->hooks->pre_write = NULL;
  atclient_connection_hooks_set_is_pre_write_initialized(ctx, false);
}

static void atclient_connection_hooks_set_is_post_write_initialized(atclient_connection *ctx, const bool initialized) {
  if (initialized) {
    ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_POST_WRITE_INDEX] |=
        ATCLIENT_CONNECTION_HOOKS_POST_WRITE_INITIALIZED;
  } else {
    ctx->hooks->_initialized_fields[ATCLIENT_CONNECTION_HOOKS_POST_WRITE_INDEX] &=
        ~ATCLIENT_CONNECTION_HOOKS_POST_WRITE_INITIALIZED;
  }
}

static int atclient_connection_hooks_set_post_write(atclient_connection *ctx, atclient_connection_hook *hook) {
  int ret = 1;

  /*
   * 1. Validate arguments
   */
  if (ctx == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Connection is NULL\n");
    return ret;
  }

  if (!atclient_connection_hooks_is_enabled(ctx)) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Make sure to enable hooks struct before trying to set a hook\n");
    return ret;
  }

  if (hook == NULL) {
    ret = 1;
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Hook is NULL\n");
    return ret;
  }

  if (atclient_connection_hooks_is_post_write_initialized(ctx)) {
    atclient_connection_hooks_unset_post_write(ctx);
  }

  ctx->hooks->post_write = hook;
  atclient_connection_hooks_set_is_post_write_initialized(ctx, true);

  ret = 0;
  goto exit;
exit: { return ret; }
}

static void atclient_connection_hooks_unset_post_write(atclient_connection *ctx) {
  ctx->hooks->post_write = NULL;
  atclient_connection_hooks_set_is_post_write_initialized(ctx, false);
}