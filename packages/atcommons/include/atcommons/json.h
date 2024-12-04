#ifndef ATCLIENT_JSON_H
#define ATCLIENT_JSON_H
#ifdef __cplusplus
extern "C" {
#endif

// NOTE: there are two platform specific files:
// - atchops/platform.h
// - atcommons/json.h

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(_WIN32)
#define ATCOMMONS_JSON_PROVIDER_CJSON
#include <cJSON.h> // IWYU pragma: export

#elif defined(CONFIG_IDF_TARGET_ESP32)
#define ATCOMMONS_JSON_PROVIDER_CJSON
#include <cjson.h> // IWYU pragma: export

#elif defined(TARGET_PORTENTA_H7)
#define ATCOMMONS_JSON_PROVIDER_CJSON
#define ATCOMMONS_JSON_PROVIDER_ARDUINO

// This file will be injected into the Arduino build by the generator
// search for atsdk_cjson.h.template in the generators directory
#include <atsdk_cjson.h>

#else
#error "unable to resolve json provider for platform"
#endif

#ifdef __cplusplus
}
#endif
#endif
