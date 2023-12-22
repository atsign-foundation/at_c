#include <stdlib.h>
#include "atclient/atevent.h"

AtEvent* atevent_init(AtEventType event_type) {
    AtEvent* event = (AtEvent*)malloc(sizeof(AtEvent));
    event->event_type = event_type;
    event->event_data = cJSON_CreateObject();
    return event;
}

char* atevent_to_string(AtEventType event) {
    switch(event) {
        case 0: return "AT_EVENT_TYPE_NONE";
        case 1: return "AT_EVENT_TYPE_SHARED_KEY_NOTIFICATION";
        case 2: return "AT_EVENT_TYPE_UPDATE_NOTIFICATION";
        case 3: return "AT_EVENT_TYPE_DELETE_NOTIFICATION";
        case 4: return "AT_EVENT_TYPE_UPDATE_NOTIFICATION_TEXT";
        case 5: return "AT_EVENT_TYPE_STATS_NOTIFICATION";
        case 6: return "AT_EVENT_TYPE_MONITOR_HEARTBEAT_ACK";
        case 7: return "AT_EVENT_TYPE_MONITOR_EXCEPTION";
        case 8: return "AT_EVENT_TYPE_DECRYPTED_UPDATE_NOTIFICATION";
        case 9: return "AT_EVENT_TYPE_USER_DEFINED";
        default: return "AT_EVENT_TYPE_UNKNOWN";
    }
}

void atevent_queue_init(AtEventQueue* queue) {
    queue->front = queue->rear = queue->size = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
}

void atevent_enqueue(AtEventQueue* queue, AtEvent* event) {
    pthread_mutex_lock(&queue->mutex);

    while (queue->size == MAX_QUEUE_SIZE) {
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }

    AtEvent* event_copy = atevent_new_event(event->event_type);
    event_copy->event_data = cJSON_Duplicate(event->event_data, 1);

    queue->events[queue->rear] = event_copy;
    queue->rear = (queue->rear + 1) % MAX_QUEUE_SIZE;
    queue->size++;

    pthread_cond_signal(&queue->not_empty);

    pthread_mutex_unlock(&queue->mutex);
}

AtEvent* atevent_dequeue(AtEventQueue* queue) {
    pthread_mutex_lock(&queue->mutex);

    while (queue->size == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }

    AtEvent* event = queue->events[queue->front];
    queue->front = (queue->front + 1) % MAX_QUEUE_SIZE;
    queue->size--;

    pthread_cond_signal(&queue->not_full);

    pthread_mutex_unlock(&queue->mutex);

    return event;
}

void atevent_queue_destroy(AtEventQueue* queue) {
    while (queue->size > 0) {
        AtEvent* event = atevent_dequeue(queue);
        cJSON_Delete(event->event_data);
        free(event);
    }

    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
}
