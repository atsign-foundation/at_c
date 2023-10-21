#include "atclient/connection.h"
#include "atclient/atkeys.h"

typedef struct atclient_ctx
{
    atclient_connection_ctx root_connection;
    atclient_connection_ctx secondary_connection;
} atclient_ctx;

void atclient_init(atclient_ctx *ctx);
int atclient_init_root_connection(atclient_ctx *ctx, const char *roothost, const int rootport);
int atclient_init_secondary_connection(atclient_ctx *ctx, const char *secondaryhost, const int secondaryport);
int atclient_pkam_authenticate(atclient_ctx *ctx, atclient_atkeys atkeys, const char *atsign);
int atclient_put(atclient_ctx *ctx, const char *key, const char *value);
int atclient_get(atclient_ctx *ctx, const char *key, char *value, const unsigned long valuelen);
int atclient_delete(atclient_ctx *ctx, const char *key);
void atclient_free(atclient_ctx *ctx);