#ifndef ATCHOPS_CONSTANTS_H
#define ATCHOPS_CONSTANTS_H
#ifdef __cplusplus
extern "C" {
#endif

#include <atchops/platform.h> // IWYU pragma: keep

// Only define this if it isn't defined
// Consumers of the SDK should be able to override it so their personalization
// isn't open source
// TODO: later provide more intentional ways of forcing consumers of the SDK
// to override this
#ifndef ATCHOPS_RNG_PERSONALIZATION
#define ATCHOPS_RNG_PERSONALIZATION "@atchops12345"
#endif

#ifdef __cplusplus
}
#endif
#endif
