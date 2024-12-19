#ifndef ATCHOPS_PLATFORM_H
#define ATCHOPS_PLATFORM_H

// NOTE: there are two platform specific files:
// - atchops/platform.h
// - atcommons/json.h

// Platforms we support

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define ATCHOPS_TARGET_UNIX

#elif defined(_WIN32)
#define ATCHOPS_TARGET_WINDOWS

#elif defined(CONFIG_IDF_TARGET_ESP32)
#define ATCHOPS_TARGET_ESPIDF

#endif
#endif
