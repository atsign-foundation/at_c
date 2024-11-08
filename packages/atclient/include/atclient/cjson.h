#ifndef ATCLIENT_CJSON_H
#define ATCLIENT_CJSON_H

#if defined(CONFIG_IDF_TARGET_ESP32)
#include <cjson.h> // IWYU pragma: export
#else
#include <cJSON.h> // IWYU pragma: export
#endif

#endif
