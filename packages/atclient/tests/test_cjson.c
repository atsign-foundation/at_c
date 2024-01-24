

#include <cJSON/cJSON.h>

int main()
{
    int ret = 1; // error by default

    cJSON *root = cJSON_CreateObject();
    ret = 0;

    goto exit;

exit:
{
    return ret;
}
}