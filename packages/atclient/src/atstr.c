#include <string.h>
#include <stdlib.h>
#include "atclient/atstr.h"

void atclient_atstr_init(atclient_atstr *atstr, unsigned long bufferlen)
{
    memset(atstr, 0, sizeof(atclient_atstr));
    atstr->len = bufferlen;
    // atstr->str = (char *)malloc(sizeof(char) * atstr->len);
    atstr->str = (char *)calloc(atstr->len, sizeof(char));
    atstr->olen = 0;
}

void atclient_atstr_free(atclient_atstr *atstr)
{
    free(atstr->str);
}
