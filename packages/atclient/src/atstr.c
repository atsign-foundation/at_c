#include <string.h>
#include <stdlib.h>
#include "atclient/atstr.h"
#include "atclient/atlogger.h"

#define TAG "atstr"

void atclient_atstr_init(atclient_atstr *atstr, unsigned long bufferlen)
{
    memset(atstr, 0, sizeof(atclient_atstr));
    atstr->len = bufferlen;
    atstr->str = (char *) malloc(sizeof(char) * atstr->len);
    atstr->olen = 0;
}

void atclient_atstr_init_literal(atclient_atstr *atstr, const char *str)
{
    atclient_atstr_init(atstr, strlen(str));
    atclient_atstr_set(atstr, str, strlen(str));
}

int atclient_atstr_set_literal(atclient_atstr *atstr, const char *str)
{
    int ret = 1;
    ret = atclient_atstr_set(atstr, str, strlen(str));
    if(ret != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed");
        goto exit;
    }
    goto exit;
exit:
{
    return ret;
}
}

int atclient_atstr_set(atclient_atstr *atstr, const char *str, const unsigned long len)
{
    int ret = 1;

    if(len > atstr->len)
    {
        ret = 1;
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "len > atstr->len (%d > %d)", len, atstr->len);
        goto exit;
    }

    memcpy(atstr->str, str, len);
    atstr->olen = len;

    ret = 0;
    goto exit;

exit:
{
    return ret;
}
}

int atclient_atstr_copy(atclient_atstr *atstr, atclient_atstr *data)
{
    int ret = 1;
    ret = atclient_atstr_set(atstr, data->str, data->olen);
    if(ret != 0)
    {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set failed");
        goto exit;
    }
    goto exit;
exit:
{
    return ret;
}
}

void atclient_atstr_free(atclient_atstr *atstr)
{
    free(atstr->str);
}
