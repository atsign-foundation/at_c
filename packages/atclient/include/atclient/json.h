#ifndef ATCLIENT_JSON_H
#define ATCLIENT_JSON_H
#ifdef __cplusplus
extern "C" {
#endif

// NOTE: there are two platform specific files:
// - atchops/platform.h
// - atclient/json.h

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(_WIN32) || defined(CONFIG_IDF_TARGET_ESP32)
#define ATCOMMONS_JSON_PROVIDER_CJSON
#endif

#if __has_include(<cJSON.h>)
#include <cJSON.h> // IWYU pragma: export
#elif __has_include(<cjson/cJSON.h>)
#include <cjson/cJSON.h> // IWYU pragma: export
#elif __has_include(<cjson.h>)
#include <cjson.h> // IWYU pragma: export
#endif

#ifdef __cplusplus
}
#endif
#endif
