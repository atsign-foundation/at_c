#include <string.h>
#include "atclient/atkey.h"
#include "atclient/constants.h"
#include "atclient/atlogger.h"

#define TAG "test_atkey_to_string"

// Test 1: public keys
// 1A: cached public key
#define TEST_ATKEY_TO_STRING_1A "cached:public:publickey@bob"
// 1B: non-cached public key
#define TEST_ATKEY_TO_STRING_1B "public:publickey@alice"
// 1C. non-cached public key with namespace
#define TEST_ATKEY_TO_STRING_1C "public:name.wavi@jeremy"
// 1D. cached public key with namespace
#define TEST_ATKEY_TO_STRING_1D "cached:public:name.wavi@jeremy"
// Test 2: shared keys
// 2A: non-cached shared key with namespace
#define TEST_ATKEY_TO_STRING_2A "@alice:name.wavi@bob"
// 2B: cached shared key without namespace
#define TEST_ATKEY_TO_STRING_2B "cached:@bob:name@alice"
// 2C: non-cached shared key without namespace
#define TEST_ATKEY_TO_STRING_2C "@bob:name@alice"
// 2D: cached shared key with namespace
#define TEST_ATKEY_TO_STRING_2D "cached:@bob:name.wavi@alice"
// Test 3: private hidden keys
// 3A: private hidden key
#define TEST_ATKEY_TO_STRING_3A "_lastnotificationid@alice123_4😘"
// Test 4: self keys
// 4A: self key with no namespace
#define TEST_ATKEY_TO_STRING_4A "name@alice"
// 4B: self key with namespace
#define TEST_ATKEY_TO_STRING_4B "name.wavi@jeremy_0"

static int test1a()
{
    int ret = 1;

    atclient_atkey atkey;
    atclient_atkey_init(&atkey);

    atclient_atstr string;
    atclient_atstr_init(&string, ATKEY_GENERAL_BUFFER_SIZE);

    const char *expected = TEST_ATKEY_TO_STRING_1A;
    const unsigned long expectedlen = strlen(expected);

    atkey.metadata.iscached = 1;
    atkey.metadata.ispublic = 1;
    atkey.atkeytype = ATCLIENT_ATKEY_TYPE_PUBLICKEY;

    ret = atclient_atstr_set_literal(&(atkey.name), "publickey");
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
        goto exit;
    }

    ret = atclient_atstr_set_literal(&(atkey.sharedby), "@bob");
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atstr_set_literal failed\n");
        goto exit;
    }

    ret = atclient_atkey_to_string(atkey, string.str, string.len, &string.olen);
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "atclient_atkey_to_string failed\n");
        goto exit;
    }

    ret = strncmp(string.str, expected, expectedlen);
    if(ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "expected: \"%s\", actual: \"%s\"\n", expected, string.str);
        ret = 1;
        goto exit;
    }

    ret = 0;
    goto exit;
exit:
{
    atclient_atkey_free(&atkey);
    atclient_atstr_free(&string);
    return ret;
}
}

int main()
{
    int ret = 1;

    atclient_atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_ERROR);

    ret = test1a();
    if (ret != 0)
    {
        atclient_atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "test1a failed\n");
        goto exit;
    }

    ret = 0;
    goto exit;
exit:
{
    return ret;
}
}