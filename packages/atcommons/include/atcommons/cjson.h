#ifndef ATCOMMONS_CJSON_H
#define ATCOMMONS_CJSON_H

#if defined(CONFIG_IDF_TARGET_ESP32)
#include <cjson.h>
#else
#include "cJSON.h"
#endif

#endif
