#include <string.h>
#include <stdlib.h>
#include "atclient/atsign.h"

void atclient_atsign_init(atclient_atsign *atsign)
{
    memset(atsign, 0, sizeof(atclient_atsign));
    atsign->atsignlen = ATSIGN_BUFFER_SIZE;
    atsign->atsignstr = (char *)malloc(sizeof(char) * atsign->atsignlen);
    atsign->atsignolen = 0;
}

void atclient_atsign_free(atclient_atsign *atsign)
{
    free(atsign->atsignstr);
}

int atclient_atsign_create(atclient_atsign *atsign, const char *atsignstr, unsigned long atsignstrlen)
{
    int ret = 1;
    if (atsignstrlen > atsign->atsignlen)
    {
        ret = -1; // insufficient buffer size
        goto exit;
    }
    strncpy(atsign->atsignstr, atsignstr, atsignstrlen);
    atsign->atsignolen = atsignstrlen;
    ret = 0;

    goto exit;

exit:
{
    return ret;
}
}
