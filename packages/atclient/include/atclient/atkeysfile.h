#pragma once

typedef struct atclient_atkeysfile {
    unsigned long aespkampublickeylen;
    unsigned char *aespkampublickeystr;
    unsigned long aespkampublickeyolen;

    unsigned long aespkamprivatekeylen;
    unsigned char *aespkamprivatekeystr;
    unsigned long aespkamprivatekeyolen;

    unsigned long aesencryptpublickeylen;
    unsigned char *aesencryptpublickeystr;
    unsigned long aesencryptpublickeyolen;

    unsigned long aesencryptprivatekeylen;
    unsigned char *aesencryptprivatekeystr;
    unsigned long aesencryptprivatekeyolen;

    unsigned long selfencryptionkeylen;
    unsigned char *selfencryptionkeystr;
    unsigned long selfencryptionkeyolen;
} atclient_atkeysfile;

void atclient_atkeysfile_init(atclient_atkeysfile *atkeysfile);
int atclient_atkeysfile_read(atclient_atkeysfile *atkeysfile, const char *path);
int atclient_atkeysfile_write(atclient_atkeysfile *atkeysfile, const char *path, const char *atsign);
void atclient_atkeysfile_free(atclient_atkeysfile *atkeysfile);
