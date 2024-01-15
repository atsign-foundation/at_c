#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "atclient/metadata.h"
#include "atclient/constants.h"
#include <time.h>
#include <sys/time.h>
#include "cJSON.h"

void atclient_atkey_metadata_init(atclient_atkey_metadata *metadata)
{
    memset(metadata, 0, sizeof(atclient_atkey_metadata));

    atclient_atstr_init(&(metadata->createdby), ATSIGN_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->updatedby), ATSIGN_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->createdat), DATE_STR_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->updatedat), DATE_STR_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->sharedkeyenc), GENERAL_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->pubkeycs), GENERAL_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->ivnonce), GENERAL_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->enckeyname), GENERAL_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->encalgo), GENERAL_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->skeenckeyname), GENERAL_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->skeencalgo), GENERAL_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->availableat), DATE_STR_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->expiresat), DATE_STR_BUFFER_LENGTH);
    atclient_atstr_init(&(metadata->refreshat), DATE_STR_BUFFER_LENGTH);
}

int atclient_atkey_metadata_from_string(atclient_atkey_metadata *metadata, const char *metadatastr)
{
    return 1; // TODO: implement
}

int atclient_atkey_metadata_to_string(atclient_atkey_metadata *metadata, char **result_ptr)
{
    size_t size = 100;
    char *result = malloc(size);
    if (result == NULL)
    {
        return -1;
    }
    result[0] = '\0';

    char buf[50];

    if (metadata->ttl != 0)
    {
        snprintf(buf, 50, "%ld", metadata->ttl);
        add_field(&result, &size, ":ttl:", buf);
    }
    if (metadata->ttb != 0)
    {
        snprintf(buf, 50, "%ld", metadata->ttb);
        add_field(&result, &size, ":ttb:", buf);
    }
    if (metadata->ttr != 0)
    {
        snprintf(buf, 50, "%ld", metadata->ttr);
        add_field(&result, &size, ":ttr:", buf);
    }
    if (metadata->ccd != 0)
    {
        snprintf(buf, 50, "%d", metadata->ccd);
        add_field(&result, &size, ":ccd:", buf);
    }
    if (metadata->datasignature.str != NULL)
    {
        if (metadata->datasignature.str[0] != '\0')
        {
            add_field(&result, &size, ":dataSignature:", metadata->datasignature.str);
        }
    }
    if (metadata->sharedkeyenc.str != NULL)
    {
        if (metadata->sharedkeyenc.str[0] != '\0')
        {
            add_field(&result, &size, ":sharedKeyEnc:", metadata->sharedkeyenc.str);
        }
    }
    if (metadata->pubkeycs.str != NULL)
    {
        if (metadata->pubkeycs.str[0] != '\0')
        {
            add_field(&result, &size, ":pubKeyCS:", metadata->pubkeycs.str);
        }
    }
    if (metadata->isbinary)
    {
        add_field(&result, &size, ":isBinary:", "true");
    }
    else
    {
        add_field(&result, &size, ":isBinary:", "false");
    }
    if (metadata->isencrypted)
    {
        add_field(&result, &size, ":isEncrypted:", "true");
    }
    else
    {
        add_field(&result, &size, ":isEncrypted:", "false");
    }
    if (metadata->ivnonce.str != NULL)
    {
        add_field(&result, &size, ":ivNonce:", metadata->ivnonce.str);
    }

    *result_ptr = result;
    return 0;
}

void add_field(char **result_ptr, size_t *size_ptr, const char *name, const char *value)
{
    char *result = *result_ptr;
    size_t size = *size_ptr;

    int needed = snprintf(NULL, 0, "%s%s", name, value) + 1;

    size_t new_size = strlen(result) + needed;
    char *new_result = realloc(result, new_size);
    if (new_result == NULL)
    {
        free(result);
        *result_ptr = NULL;
        return;
    }
    result = new_result;
    size = new_size;

    strcat(result, name);
    strcat(result, value);

    *result_ptr = result;
    *size_ptr = size;
}

void fill_atstr_from_json(cJSON *json, atclient_atstr *atstr)
{
    if (json != NULL && cJSON_IsString(json))
    {
        atstr->len = strlen(json->valuestring);
        atstr->str = malloc(atstr->len + 1);
        if (atstr->str != NULL)
        {
            strcpy(atstr->str, json->valuestring);
            atstr->olen = atstr->len;
        }
    }
}

int atclient_atkey_metadata_from_json(const char *json_str, atclient_atkey_metadata *metadata)
{
    cJSON *root = cJSON_Parse(json_str);
    if (root == NULL)
    {
        return -1;
    }

    cJSON *notification = cJSON_GetObjectItem(root, "notification");
    if (notification == NULL)
    {
        cJSON_Delete(root);
        return -1;
    }

    cJSON *json_metadata = cJSON_GetObjectItem(notification, "metadata");
    if (json_metadata == NULL)
    {
        cJSON_Delete(root);
        return -1;
    }

    cJSON *ttl = cJSON_GetObjectItem(json_metadata, "ttl");
    if (ttl != NULL && cJSON_IsNumber(ttl))
    {
        metadata->ttl = ttl->valueint;
    }

    cJSON *ttb = cJSON_GetObjectItem(json_metadata, "ttb");
    if (ttb != NULL && cJSON_IsNumber(ttb))
    {
        metadata->ttb = ttb->valueint;
    }

    cJSON *ttr = cJSON_GetObjectItem(json_metadata, "ttr");
    if (ttr != NULL && cJSON_IsNumber(ttr))
    {
        metadata->ttr = ttr->valueint;
    }

    cJSON *ccd = cJSON_GetObjectItem(json_metadata, "ccd");
    if (ccd != NULL && cJSON_IsNumber(ccd))
    {
        metadata->ccd = ccd->valueint;
    }

    cJSON *isbinary = cJSON_GetObjectItem(json_metadata, "isBinary");
    if (isbinary != NULL && cJSON_IsBool(isbinary))
    {
        metadata->isbinary = cJSON_IsTrue(isbinary);
    }

    cJSON *isencrypted = cJSON_GetObjectItem(json_metadata, "isEncrypted");
    if (isencrypted != NULL && cJSON_IsBool(isencrypted))
    {
        metadata->isencrypted = cJSON_IsTrue(isencrypted);
    }

    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "createdby"), &metadata->createdby);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "updatedby"), &metadata->updatedby);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "createdat"), &metadata->createdat);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "updatedat"), &metadata->updatedat);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "status"), &metadata->status);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "datasignature"), &metadata->datasignature);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "sharedkeyenc"), &metadata->sharedkeyenc);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "pubkeycs"), &metadata->pubkeycs);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "ivnonce"), &metadata->ivnonce);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "enckeyname"), &metadata->enckeyname);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "encalgo"), &metadata->encalgo);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "skeenckeyname"), &metadata->skeenckeyname);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "skeencalgo"), &metadata->skeencalgo);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "availableat"), &metadata->availableat);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "expiresat"), &metadata->expiresat);
    fill_atstr_from_json(cJSON_GetObjectItem(json_metadata, "refreshat"), &metadata->refreshat);

    cJSON_Delete(root);
    return 0;
}

void atclient_atkey_metadata_free(atclient_atkey_metadata *metadata)
{
    atclient_atstr_free(&(metadata->createdat));
    atclient_atstr_free(&(metadata->updatedat));
    atclient_atstr_free(&(metadata->sharedkeyenc));
    atclient_atstr_free(&(metadata->pubkeycs));
    atclient_atstr_free(&(metadata->ivnonce));
    atclient_atstr_free(&(metadata->enckeyname));
    atclient_atstr_free(&(metadata->encalgo));
    atclient_atstr_free(&(metadata->skeenckeyname));
    atclient_atstr_free(&(metadata->skeencalgo));
    atclient_atstr_free(&(metadata->availableat));
    atclient_atstr_free(&(metadata->expiresat));
    atclient_atstr_free(&(metadata->refreshat));
}

int tv_from_str(char *timestamp_str, struct timeval *tv)
{
    struct tm tm;
    int ret = NULL;

    ret = strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.", &tm);
    if (ret == NULL)
    {
        fprintf(stderr, "There was an error while parsing a timestamp\n");
        return 1;
    }

    char *millis_str = strstr(timestamp_str, ".");
    if (millis_str != NULL)
    {
        unsigned long millis = strtoul(millis_str + 1, NULL, 10);
        tv->tv_usec = millis * 1000;
    }
    else
    {
        tv->tv_usec = 0;
    }
    tv->tv_sec = mktime(&tm); // _mkgmtime

    return 0;
}

int tv_to_str(struct timeval *tv, char *timestamp_str)
{
    struct tm tm;

    if (localtime_r(&tv->tv_sec, &tm) == NULL)
    {
        return 1;
    }

    if (strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%dT%H:%M:%S.000%Z", &tm) == 0)
    {
        return 1;
    }

    // Manually add subsecond precision to the timestamp
    sprintf(timestamp_str + 20, "%03ld%s", tv->tv_usec / 1000, timestamp_str + 23);
    return 0;
}