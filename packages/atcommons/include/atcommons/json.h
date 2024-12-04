#ifndef ATCLIENT_JSON_H
#define ATCLIENT_JSON_H
#ifdef __cplusplus
extern "C" {
#endif

#define ATCLIENT_JSON_PROVIDER_CJSON 1
#define ATCLIENT_JSON_PROVIDER ATCLIENT_JSON_PROVIDER_CJSON

#if defined(CONFIG_IDF_TARGET_ESP32)
#include <cjson.h> // IWYU pragma: export
#else
#include <cJSON.h> // IWYU pragma: export
#endif

#ifdef __cplusplus
}
#endif
#endif
