#ifndef ATSIGN_H
#define ATSIGN_H

#define ATSIGN_BUFFER_SIZE 2048 // atsigns will never be this long

typedef struct atclient_atsign
{
    unsigned long atsignlen;
    char *atsignstr;
    unsigned long atsignolen;
} atclient_atsign;

void atclient_atsign_init(atclient_atsign *atsign);
void atclient_atsign_free(atclient_atsign *atsign);
int atclient_atsign_create(atclient_atsign *atsign, const char *atsignstr, unsigned long atsignstrlen);

#endif