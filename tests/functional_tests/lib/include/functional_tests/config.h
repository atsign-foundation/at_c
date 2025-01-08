#ifndef FUNCTIONAL_TESTS_CONFIG_H
#define FUNCTIONAL_TESTS_CONFIG_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

// you can change this value at compile time by using `-DATDIRECTORY_HOST="vip.ve.atsign.zone"` in the CMake configure command
#ifndef ATDIRECTORY_HOST
#define ATDIRECTORY_HOST "root.atsign.org"
#endif

// you can change this value at compile time by using `-DATDIRECTORY_PORT=64` in the CMake configure command
#ifndef ATDIRECTORY_PORT
#define ATDIRECTORY_PORT 64
#endif 

// you can change this value at compile time  by using `-DFIRST_ATSIGN="@alice🛠"` in the CMake configure command
#ifndef FIRST_ATSIGN
#define FIRST_ATSIGN "@12alpaca"
#endif

// you can change this value at compile time by using `-DSECOND_ATSIGN="@bob🛠"` in the CMake configure command
#ifndef SECOND_ATSIGN
#define SECOND_ATSIGN "@12snowboating"
#endif

// you can change this value at compile time by using `-DFIRST_ATSIGN_ATSERVER_HOST="vip.ve.atsign.zone"` in the CMake configure command
#ifndef FIRST_ATSIGN_ATSERVER_HOST
#define FIRST_ATSIGN_ATSERVER_HOST "228aafb0-94d3-5aa2-a3b3-e36af115480d.swarm0002.atsign.zone"
#endif

// you can change this value at compile time by using `-DFIRST_ATSIGN_ATSERVER_PORT=25000` in the CMake configure command
#ifndef FIRST_ATSIGN_ATSERVER_PORT
#define FIRST_ATSIGN_ATSERVER_PORT 6943
#endif

// you can change this value at compile time by using `-DSECOND_ATSIGN_ATSERVER_HOST="vip.ve.atsign.zone"` in the CMake configure command
#ifndef SECOND_ATSIGN_ATSERVER_HOST
#define SECOND_ATSIGN_ATSERVER_HOST "96424e26-f67f-5834-84a4-220b47fd7843.swarm0002.atsign.zone"
#endif

// you can change this value at compile time by using `-DSECOND_ATSIGN_ATSERVER_PORT=25000` in the CMake configure command
#ifndef SECOND_ATSIGN_ATSERVER_PORT
#define SECOND_ATSIGN_ATSERVER_PORT 6942
#endif

#ifdef __cplusplus
}
#endif
#endif
