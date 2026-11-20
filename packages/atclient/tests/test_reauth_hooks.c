// What becomes of an atclient's connection and its hooks when it is
// authenticated again, in particular when that authentication fails part-way.
//
// The atclient runs for real. Only the TLS socket is replaced, by the scripted
// atServer below: this file defines every function of socket_mbedtls.c, so the
// linker never pulls that object out of the atclient library.
#include <atclient/atclient.h>
#include <atclient/atkeys.h>
#include <atclient/connection.h>
#include <atclient/connection_hooks.h>
#include <atclient/socket.h>
#include <atlogger/atlogger.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Throwaway RSA-2048 key generated for tests only
static const char *TEST_PRIVATE_KEY_B64 =
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCWkE9G3HhNcsSi1z1R0N3z0ep1shnlQooP96l09sa5TnJk"
    "yBj21M5RCgMmqVVWWeYTI6fUh80d4ImCZrygaR52vSV9nfMPomBxsWRLImgbB6Hvudlf8TWkpMIfF4SBqC97aqG9eXsfrEiU"
    "jPCj6xPJG3D4cBjsZGbmnn67wiXe3EV+eHDXO6leQ+lEaWN6vFm4ddCJ6d1f6S9Wiyy3nCL95xxzkYSiSUYTTvv2Kn+qcFX9"
    "PA0P5MF68/zTKXw4WJy9xDlK75hBrkvddnYXwu3qKJzisUelsWUiDy8xzvksor23QxnU1NL0KcFpkuFN3bMY/zd8+gPfL65K"
    "nbGbbi4RAgMBAAECggEABiN8F/eFMCMtwTXlWiCZ7Aby+Dl6tM4xstT2I76r+4InR9Sgr++dOdCesETXJd4kc0NQ5GllA4LU"
    "GGz349JlW5H6pVR7RHfqVrhUzntoozF8eLmrEy5ScZQGFh5vWJny1aVTUtZRHsl3bBcS+JvtApYL1RU87uZpC54KrL0Nrjhc"
    "2ImQ4ZmsUMHcx+9hS/QXGkuyCRbKkkIKYIRKf5Lem7ECY/eSh3uXOMkKuoOcysDAhTqsxploaIS6l+j+JUI6NJRFVXuKwUnq"
    "kyYvT3/cka++QBTXgGlpTZzQyrMNuy42N7UXMJU6KMGwcDepkqqou8KzyliR/Bpw8/YTmPS8AQKBgQDKvTrbfe+cpMzkkR7m"
    "DVOU1tnD/GA+La2UnK6q+Vau51+PHvZ0WLt7LHnovvTbcHPa5dvhGRLwe3dBSy76k4QtfBGGb8HXmmGFd7uWtA0QF+DO0u9/"
    "Vr///hoMqgF3+A0gASwei55g7K62pM7VHxVNkgQWTuzwxTJzumN2Y3RoCQKBgQC+HiKfAnEKMTVWikUBtPDoSx0qwM/JQFqV"
    "4dhittva7rW5Tw1pSbvnm7F7HU8AW/I0ANeMarrq35HlPg3auLjko/OqQc0nqesQQmZTWQ8nQQFLx2mtvsJ57bf4a9dtckpe"
    "SzvgrrrIERN0W8ALMXF1xkTA40k16UcXdX59Oj5HyQKBgCmbkFq/i89wGwTFq7u2/HJNbb/FKdNY+IjJZyd7qIiYv4nV5uqV"
    "01RCGnrjxcjLWVuRVQDrbnGgRSdHUMroP3Y+QjJ++R9Qdbc4jW0uYofs/pwzuic+HIVjFuGGemquo7LvyqgyKzzlFi4xwKkI"
    "igyzbNdPN11qeyI5HHSNkLRRAoGAew9cj5pv+w3xHYwwsLMjgOkl/weBOB6MxBnFC9ibJPKA9GsEHlPY6kkwL6W//laFxz2I"
    "SF7JkMCYWk+5fgs1uuGZFmqzVeo5unOQcoDiOyFrqlZwxEMG9Q93lriPYEurca+3GW9gfaH3+shs3ZHqhDaLSGOWfuv51Wh7"
    "MKnjqGkCgYEAlJzJeoBIoyC4jZ1Vmm3kaJKQ/Q3L/KsnNnHH8ajEXHI6wdy5oD2CsF7VnodduHwVpNkVZMp15IXClr/KbYWL"
    "y+cpsyRBeiGoglreO2lxAuqP51FjQriaT5E/ox7nvy2jATAjX8i6BDLk69F0+6QL1cuHTHhz4Y6bkDCJrocSNfY=";

// ---------------------------------------------------------------------------
// The scripted atServer
// ---------------------------------------------------------------------------

#define PROMPT_ANON "@"
#define PROMPT_AUTHED "@alice@"

static struct {
  char rx[4096]; // sent by the atServer, not yet read by the client
  size_t rx_len;
  char late[256]; // a reply still on its way: lands once a read has timed out
  bool authenticated;
  bool slow_pkam; // the atServer takes longer than the read timeout to answer the next pkam:
  bool open;
  int connects;
} srv;

static void srv_reply(const char *line, bool is_late) {
  char *dst = is_late ? srv.late : srv.rx + srv.rx_len;
  size_t room = is_late ? sizeof(srv.late) : sizeof(srv.rx) - srv.rx_len;
  int n = snprintf(dst, room, "%s\n%s", line, srv.authenticated ? PROMPT_AUTHED : PROMPT_ANON);
  if (!is_late) {
    srv.rx_len += (size_t)n;
  }
}

void atclient_tls_socket_init(struct atclient_tls_socket *socket) { (void)socket; }
void atclient_tls_socket_free(struct atclient_tls_socket *socket) {
  (void)socket;
  srv.open = false;
}
void atclient_tls_socket_set_read_timeout(struct atclient_tls_socket *socket, const int timeout_ms) {
  (void)socket;
  (void)timeout_ms;
}
int atclient_tls_socket_configure(struct atclient_tls_socket *socket, unsigned char *ca_pem, size_t ca_pem_len) {
  (void)socket;
  (void)ca_pem;
  (void)ca_pem_len;
  return 0;
}
int atclient_tls_socket_disconnect(struct atclient_tls_socket *socket) {
  (void)socket;
  srv.open = false;
  return 0;
}

// A new connection: nothing the old one was owed arrives on it
int atclient_tls_socket_connect(struct atclient_tls_socket *socket, const char *host, const uint16_t port) {
  (void)socket;
  (void)host;
  (void)port;
  srv.connects++;
  srv.open = true;
  srv.authenticated = false;
  srv.late[0] = '\0';
  memcpy(srv.rx, PROMPT_ANON, strlen(PROMPT_ANON));
  srv.rx_len = strlen(PROMPT_ANON);
  return 0;
}

static bool is_verb(const unsigned char *value, size_t value_len, const char *verb) {
  return value_len >= strlen(verb) && strncmp((const char *)value, verb, strlen(verb)) == 0;
}

int atclient_tls_socket_write(struct atclient_tls_socket *socket, const unsigned char *value, size_t value_len) {
  (void)socket;
  if (!srv.open) {
    return 1;
  }
  if (is_verb(value, value_len, "from:")) {
    srv_reply("data:_3d9a0be1-fd4b-4b46-ae5d-39af4a5cd3d8@alice:f7c1b1c0-3c1b-4f0a-9d2e-2f4b9c2d7e11", false);
  } else if (is_verb(value, value_len, "pkam:")) {
    srv.authenticated = true;
    srv_reply("data:success", srv.slow_pkam);
    srv.slow_pkam = false;
  } else if (is_verb(value, value_len, "noop:")) {
    srv_reply("data:ok", false);
  } else if (is_verb(value, value_len, "scan")) {
    srv_reply("data:[\"public:signing_publickey@alice\"]", false);
  } else if (is_verb(value, value_len, "llookup:")) {
    // longer than the 64 bytes the caller below has room for
    srv_reply("data:0123456789012345678901234567890123456789012345678901234567890123456789", false);
  } else {
    srv_reply("error:AT0003-Invalid syntax", false);
  }
  return 0;
}

int atclient_tls_socket_read(struct atclient_tls_socket *socket, unsigned char **value, size_t *value_len,
                             const struct atclient_socket_read_options options) {
  (void)socket;
  if (!srv.open) {
    return 1;
  }
  char *end = memchr(srv.rx, options.until_char, srv.rx_len);
  if (end == NULL) {
    // Nothing arrived within the read timeout. A reply that was on its way
    // lands after the client has given up on it.
    if (srv.late[0] != '\0') {
      size_t late_len = strlen(srv.late);
      memcpy(srv.rx + srv.rx_len, srv.late, late_len);
      srv.rx_len += late_len;
      srv.late[0] = '\0';
    }
    return ATCLIENT_SSL_TIMEOUT_EXITCODE;
  }
  size_t n = (size_t)(end - srv.rx) + 1;
  if (value != NULL) {
    *value = malloc(n);
    if (*value == NULL) {
      return 1;
    }
    memcpy(*value, srv.rx, n);
  }
  if (value_len != NULL) {
    *value_len = n;
  }
  memmove(srv.rx, srv.rx + n, srv.rx_len - n);
  srv.rx_len -= n;
  return 0;
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

static int failures = 0;

static void check(bool ok, const char *what) {
  if (!ok) {
    printf("FAIL: %s\n", what);
    failures++;
  } else {
    printf("ok: %s\n", what);
  }
}

static atclient client;
static atclient_atkeys atkeys;
static atclient_authenticate_options options;
static int hook_calls = 0;
static bool hook_reconnects = false;

static int authenticate(void) { return atclient_pkam_authenticate(&client, "@alice", &atkeys, &options, NULL); }

// As an application that keeps its connection up does: check it before each
// write, and authenticate again if it has gone
static int pre_write_hook(atclient_connection_hook_params *params) {
  (void)params;
  hook_calls++;
  if (!hook_reconnects || atclient_is_connected(&client)) {
    return 0;
  }
  return authenticate();
}

static int send(const char *command, char *reply, size_t reply_size) {
  size_t reply_len = 0;
  memset(reply, 0, reply_size);
  return atclient_connection_send(&client.atserver_connection, (const unsigned char *)command, strlen(command),
                                  (unsigned char *)reply, reply_size, &reply_len);
}

int main(void) {
  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_INFO);
  char reply[64];

  atclient_atkeys_init(&atkeys);
  if (atclient_atkeys_populate_pkam_private_key(&atkeys, TEST_PRIVATE_KEY_B64, strlen(TEST_PRIVATE_KEY_B64)) != 0) {
    printf("FAIL: test setup\n");
    return 1;
  }
  // an atServer address, so that no atDirectory lookup is made
  options.atserver_host = "alice.example";
  options.atserver_port = 6464;
  options.atdirectory_host = NULL;
  options.atdirectory_port = 0;
  atclient_init(&client);

  // Hooks set before the first authentication
  int ret = atclient_connection_hooks_enable(&client.atserver_connection);
  if (ret == 0) {
    ret = atclient_connection_hooks_set(&client.atserver_connection, ATCLIENT_CONNECTION_HOOK_TYPE_PRE_WRITE,
                                        pre_write_hook);
  }
  check(ret == 0 && authenticate() == 0, "@alice authenticates");
  hook_calls = 0;
  check(send("scan\r\n", reply, sizeof(reply)) == 0 && hook_calls == 1,
        "given hooks set before authenticating, when @alice sends a command, then her pre-write hook is called");

  check(authenticate() == 0 && srv.connects == 2, "@alice authenticates again");
  hook_calls = 0;
  check(send("scan\r\n", reply, sizeof(reply)) == 0 && hook_calls == 1,
        "when @alice has authenticated again, then her pre-write hook is still called");

  check(send("llookup:big@alice\r\n", reply, sizeof(reply)) != 0,
        "when a reply is longer than the caller has room for, then the send fails");
  check(send("noop:0\r\n", reply, sizeof(reply)) == 0 && strcmp(reply, "data:ok") == 0,
        "and the next command reads its own reply");

  printf("\n--- the atServer is slower than the read timeout to answer pkam:\n");
  srv.slow_pkam = true;
  check(authenticate() != 0, "when the atServer's reply to pkam: doesn't arrive in time, then authenticating fails");
  check(!srv.open, "and the connection it was made on is closed");
  check(!atclient_is_connected(&client), "and @alice is not connected");
  check(atclient_connection_hooks_is_enabled(&client.atserver_connection), "and her hooks are still set");
  hook_calls = 0;
  check(send("noop:0\r\n", reply, sizeof(reply)) != 0 && hook_calls == 1 && reply[0] == '\0',
        "and a command she sends fails, her pre-write hook having been called, without reading the late reply");

  printf("\n--- her pre-write hook reconnects\n");
  hook_reconnects = true;
  int connects_before = srv.connects;
  check(send("noop:0\r\n", reply, sizeof(reply)) == 0 && strcmp(reply, "data:ok") == 0,
        "given a pre-write hook that reconnects, when @alice sends a command after a failed authentication, then it is "
        "sent on a new connection and reads its own reply");
  check(srv.connects == connects_before + 1, "and one new connection was made");

  printf("\n--- the reconnect in her hook fails\n");
  atclient_connection_disconnect(&client.atserver_connection);
  srv.slow_pkam = true;
  check(send("noop:0\r\n", reply, sizeof(reply)) != 0, "when the reconnect in her hook fails, then the command fails");
  check(send("noop:0\r\n", reply, sizeof(reply)) == 0 && strcmp(reply, "data:ok") == 0,
        "and her next command reconnects and reads its own reply");

  atclient_free(&client);
  check(!atclient_connection_hooks_is_enabled(&client.atserver_connection) && !srv.open,
        "when @alice's atclient is freed, then its connection and hooks are released");
  atclient_atkeys_free(&atkeys);

  if (failures > 0) {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  return 0;
}
