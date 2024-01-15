#ifndef ATCLIENT_CONSTANTS_H
#define ATCLIENT_CONSTANTS_H

#include <pthread.h>

#define ATSIGN_BUFFER_LENGTH 4096 // sufficient memory for atSigns

extern pthread_mutex_t should_be_running_lock;
extern pthread_mutex_t running_lock;

#endif