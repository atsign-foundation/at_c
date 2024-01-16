#ifndef ATEVENT_H
#define ATEVENT_H

#include <pthread.h>
#include <cJSON.h>

#define MAX_QUEUE_SIZE 30

typedef enum {
    AT_EVENT_TYPE_NONE = 0,
    AT_EVENT_TYPE_SHARED_KEY_NOTIFICATION = 1,
    AT_EVENT_TYPE_UPDATE_NOTIFICATION = 2,
    AT_EVENT_TYPE_DELETE_NOTIFICATION = 3,
    AT_EVENT_TYPE_UPDATE_NOTIFICATION_TEXT = 4,
    AT_EVENT_TYPE_STATS_NOTIFICATION = 5,
    AT_EVENT_TYPE_MONITOR_HEARTBEAT_ACK = 6,
    AT_EVENT_TYPE_MONITOR_EXCEPTION = 7,
    AT_EVENT_TYPE_DECRYPTED_UPDATE_NOTIFICATION = 8,
    AT_EVENT_TYPE_USER_DEFINED = 9
} AtEventType;

typedef struct {
    AtEventType event_type;
    cJSON* event_data;

} AtEvent;

typedef struct {
    AtEvent* events[MAX_QUEUE_SIZE];
    int front, rear, size;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} AtEventQueue;

AtEvent* atevent_init(AtEventType event_type);

void atevent_queue_init(AtEventQueue* queue);

void atevent_enqueue(AtEventQueue* queue, AtEvent* event);

AtEvent* atevent_dequeue(AtEventQueue* queue);

void atevent_queue_destroy(AtEventQueue* queue);

#endif
