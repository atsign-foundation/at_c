#ifndef ATCLIENT_ATKEYSFILE_H
#define ATCLIENT_ATKEYSFILE_H

#include "atclient/atstr.h"

typedef struct atclient_atkeysfile {
    atclient_atstr aespkamprivatekeystr;
    atclient_atstr aespkampublickeystr;
    atclient_atstr aesencryptprivatekeystr;
    atclient_atstr aesencryptpublickeystr;
    atclient_atstr selfencryptionkeystr;
} atclient_atkeysfile;

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile);
int atclient_atkeysfile_read(atclient_atkeysfile *atkeysfile, const char *path);
int atclient_atkeysfile_write(atclient_atkeysfile *atkeysfile, const char *path, const char *atsign);
void atclient_atkeysfile_free(atclient_atkeysfile *atkeysfile);

#endif
