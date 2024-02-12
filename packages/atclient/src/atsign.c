#include <string.h>
#include <stdio.h>
#include "atlogger/atlogger.h"
#include "atclient/atsign.h"
#include "atclient/atutils.h"

#define TAG "atsign"

void atsign_init(atsign* atsign, const char* atsign_str) {
    // Check if input_at_sign is null or empty
    if (atsign_str == NULL || strlen(atsign_str) == 0) {
        fprintf(stderr, "Error: atsign cannot be null or empty\n");
        exit(EXIT_FAILURE);
    }

    atsign->atsign = with_prefix(atsign_str);
    atsign->without_prefix_str = without_prefix(atsign_str);
}

void free_atsign(atsign* atsign) {
    free(atsign->atsign);
    free(atsign->without_prefix_str);
}

int atclient_atsign_without_at_symbol(char *atsign, const unsigned long atsignlen, unsigned long *atsignolen, const char *originalatsign, const unsigned long originalatsignlen)
{
    int ret = 1;
    if(atsignlen + 1 < originalatsignlen)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsignlen might be too low. consider allocating more buffer space. atsignlen: %d\n", atsignlen);
        ret = 1;
        goto exit;
    }

    if(originalatsignlen <= 0)
    {
        ret = 2;
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "originalatsignlen is <= 0: %lu\n", originalatsignlen);
        goto exit;
    }

    if (originalatsign[0] != '@') {
        // it did not begin with an `@` to begin with
        ret = 0;
        goto exit;
    }

    strncpy(atsign, originalatsign + 1, originalatsignlen - 1);
    *atsignolen = originalatsignlen - 1;
    ret = 0;
    goto exit;
exit:
{
    return ret;
}
}

int atclient_atsign_with_at_symbol(char *atsign, const unsigned long atsignlen, unsigned long *atsignolen, const char *originalatsign, const unsigned long originalatsignlen)
{
    int ret = 1;
    if(atsignlen + 1 < originalatsignlen)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atsignlen might be too low. consider allocating more buffer space. atsignlen: %d\n", atsignlen);
        ret = 1;
        goto exit;
    }

    if(originalatsignlen <= 0)
    {
        ret = 2;
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "originalatsignlen is <= 0: %lu\n", originalatsignlen);
        goto exit;
    }

    if (originalatsign[0] == '@') {
        // it already began with an x@x
        ret = 0;
        goto exit;
    }

    atsign[0] = '@';
    strncpy(atsign + 1, originalatsign, originalatsignlen);
    *atsignolen = originalatsignlen + 1;
    ret = 0;
    goto exit;
exit:
{
    return ret;
}
}


#endif
