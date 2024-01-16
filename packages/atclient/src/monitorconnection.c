#include <pthread.h>
#include <unistd.h>
#include "atclient/atlogger.h"
#include "atclient/monitorconnection.h"
#include "atclient/atutils.h"
#include "atclient/atevent.h"

pthread_mutex_t should_be_running_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t running_lock = PTHREAD_MUTEX_INITIALIZER;

static int run(atclient_monitor_connection_ctx *ctx, char *regex)
{
    int ret = 1;
    int first = 1;
    unsigned long olen = 0;
    char str_last_received_time[20];
    sprintf(str_last_received_time, "%lld", ctx->last_received_time);

    const char *initial_prefix = "monitor:";
    const char *strings[] = {str_last_received_time, " ", regex, "\r\n"};

    int num_strings = sizeof(strings) / sizeof(strings[0]);
    char *monitor_command = concatenate_with_prefix(initial_prefix, strings, num_strings);

    const unsigned long recvlen = 1024;
    unsigned char *recv = (unsigned char *)malloc(sizeof(unsigned char) * recvlen);
    memset(recv, 0, sizeof(unsigned char) * recvlen);

    // Send monitor command; we don't want to recv any answer now, we will be reading from the buffer later
    ret = mbedtls_ssl_write(&(ctx->monitor_connection.ssl), monitor_command, strlen((char *)monitor_command));
    if (ret < 0)
    {
        return ret;
    }
    atlogger_log("connection", ATLOGGER_LOGGING_LEVEL_INFO, "\tSENT: \"%.*s\"\n", (int)strlen((char *)monitor_command), monitor_command);

    printf("Monitor started on %s\n", ctx->atsign.atsign);
    int entered = 0;
    pthread_mutex_lock(&should_be_running_lock);
    while (ctx->should_be_running)
    {
        pthread_mutex_unlock(&should_be_running_lock);
        entered = 1;
        first = 0;
        ret = atclient_connection_readline(&(ctx->monitor_connection), recv, recvlen);
        if (ret < 0)
        {
            return ret;
        }
        printf("\tRCVD (MONITOR): %s\n", recv);

        AtEvent *event = atevent_init(AT_EVENT_TYPE_NONE);

        if (starts_with("data:ok", recv))
        {
            event->event_type = AT_EVENT_TYPE_MONITOR_HEARTBEAT_ACK;
            cJSON_AddStringToObject(event->event_data, "key", "__heartbeat__");
            cJSON_AddStringToObject(event->event_data, "value", recv + strlen("data:"));
            ctx->last_heartbeat_ack_time = current_time_millis();
        }
        else if (starts_with("data:", recv))
        {
            event->event_type = AT_EVENT_TYPE_MONITOR_EXCEPTION;
            cJSON_AddStringToObject(event->event_data, "key", "__monitorException__");
            cJSON_AddStringToObject(event->event_data, "value", recv);
            cJSON_AddStringToObject(event->event_data, "exception", "Unexpected 'data:' message from server");
        }
        else if (starts_with("error:", recv))
        {
            event->event_type = AT_EVENT_TYPE_MONITOR_EXCEPTION;
            cJSON_AddStringToObject(event->event_data, "key", "__monitorException__");
            cJSON_AddStringToObject(event->event_data, "value", recv);
            cJSON_AddStringToObject(event->event_data, "exception", "Unexpected 'data:' message from server");
        }
        else if (starts_with("notification:", recv))
        {
            event->event_data = cJSON_Parse(recv + strlen("notification:"));
            char *uuid = cJSON_GetObjectItem(event->event_data, "id")->valuestring;
            char *operation = cJSON_GetObjectItem(event->event_data, "operation")->valuestring;
            char *key = cJSON_GetObjectItem(event->event_data, "key")->valuestring;

            if (cJSON_HasObjectItem(event->event_data, "epochMillis"))
            {
                ctx->last_received_time = cJSON_GetObjectItem(event->event_data, "epochMillis")->valueint;
            }
            else
            {
                ctx->last_received_time = current_time_millis();
            }
            if (strcmp(uuid, "-1") == 0)
            {
                event->event_type = AT_EVENT_TYPE_STATS_NOTIFICATION;
            }
            else if (strcmp(operation, "update") == 0)
            {
                char *sk_prefix = (char *) malloc(strlen(ctx->atsign.atsign) + strlen(":shared_key") + 1);
                strcpy(sk_prefix, ctx->atsign.atsign);
                strcat(sk_prefix, ":shared_key");

                if (starts_with(sk_prefix, key))
                {
                    event->event_type = AT_EVENT_TYPE_SHARED_KEY_NOTIFICATION;
                }
                else
                {
                    event->event_type = AT_EVENT_TYPE_UPDATE_NOTIFICATION;
                }
            }
            else if (strcmp(operation, "delete") == 0)
            {
                event->event_type = AT_EVENT_TYPE_DELETE_NOTIFICATION;
            }
            else
            {
                event->event_type = AT_EVENT_TYPE_MONITOR_EXCEPTION;
                cJSON_AddStringToObject(event->event_data, "key", "__monitorException__");
                cJSON_AddStringToObject(event->event_data, "value", recv);
                cJSON_AddStringToObject(event->event_data, "exception", "Unknown notification operation");
                // cJSON_AddStringToObject(event->event_data, "exception", operation);
            }
        }
        else
        {
            event->event_type = AT_EVENT_TYPE_MONITOR_EXCEPTION;
            cJSON_AddStringToObject(event->event_data, "key", "__monitorException__");
            cJSON_AddStringToObject(event->event_data, "value", recv);
            cJSON_AddStringToObject(event->event_data, "exception", "Malformed response from server");
        }

        atevent_enqueue(&(ctx->queue), event);

        pthread_mutex_lock(&should_be_running_lock);
        entered = 0;
    }

    if(!entered)
    {
        pthread_mutex_unlock(&should_be_running_lock);
        entered = 0;
    }

    pthread_mutex_lock(&running_lock);
    ctx->running = 0;
    pthread_mutex_unlock(&running_lock);

    ret = atclient_connection_disconnect(&(ctx->monitor_connection));
    if (ret != 0)
    {
        return ret;
    }
    return 0;
}

static int start_monitor(atclient_monitor_connection_ctx *ctx, char *regex)
{
    int ret = 0;
    ctx->last_heartbeat_sent_time = current_time_millis();
    ctx->last_heartbeat_ack_time = current_time_millis();

    pthread_mutex_lock(&should_be_running_lock);
    ctx->should_be_running = 1;
    pthread_mutex_unlock(&should_be_running_lock);

    pthread_mutex_lock(&running_lock);
    if (!ctx->running)
    {
        ctx->running = 1;
        pthread_mutex_unlock(&running_lock);
        if (!atclient_connection_is_connected(&(ctx->monitor_connection)))
        {
            ret = atclient_connection_connect(
                &(ctx->monitor_connection),
                ctx->monitor_connection.host,
                ctx->monitor_connection.port);
            if (ret != 0)
            {
                printf("start_monitor failed to connect to secondary");
                pthread_mutex_lock(&running_lock);
                ctx->running = 0;
                pthread_mutex_unlock(&running_lock);
                goto exit;
            }
        }
        run(ctx, regex);
    }
    else
    {
        pthread_mutex_unlock(&running_lock);
    }
exit:
{
    return ret;
}
}

static int stop_monitor(atclient_monitor_connection_ctx *ctx)
{
    pthread_mutex_lock(&should_be_running_lock);
    ctx->should_be_running = 0;
    pthread_mutex_unlock(&should_be_running_lock);

    ctx->last_heartbeat_sent_time = current_time_millis();
    ctx->last_heartbeat_ack_time = current_time_millis();
    atclient_connection_disconnect(&(ctx->monitor_connection));
}

void atclient_monitor_connection_init(atclient_monitor_connection_ctx *ctx, char *atsign_str)
{
    memset(ctx, 0, sizeof(atclient_monitor_connection_ctx));
    ctx->last_received_time = 0;
    ctx->running = 0;
    ctx->should_be_running = 0;

    ctx->last_heartbeat_sent_time = current_time_millis();
    ctx->last_heartbeat_ack_time = current_time_millis();

    atclient_connection_ctx c_ctx;
    atclient_connection_init(&c_ctx);
    ctx->monitor_connection = c_ctx;

    atclient_atsign atsign;
    atsign_init(&atsign, atsign_str);
    ctx->atsign = atsign;

    AtEventQueue queue;
    atevent_queue_init(&queue);
    ctx->queue = queue;
}

int start_heartbeat(atclient_monitor_connection_ctx *ctx)
{
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, start_heartbeat_impl, ctx);
    pthread_detach(thread_id);
}

int start_heartbeat_impl(atclient_monitor_connection_ctx *ctx)
{
    while (1)
    {
        pthread_mutex_lock(&should_be_running_lock);
        if (ctx->should_be_running)
        {
            pthread_mutex_unlock(&should_be_running_lock);
            if ((!ctx->running) || ((ctx->last_heartbeat_sent_time - ctx->last_heartbeat_ack_time) >= HEARTBEAT_INVERVAL_MILLIS))
            {
                printf("Monitor heartbeats not being received");
                stop_monitor(ctx);
                long long wait_start_time = current_time_millis();
                pthread_mutex_lock(&running_lock);
                int entered = 0;
                printf("%d\n", (current_time_millis() - wait_start_time) < 5000);
                while ((ctx->running) && ((current_time_millis - wait_start_time) < 5000))
                {
                    entered = 1;
                    pthread_mutex_unlock(&running_lock);
                    printf("Wait 5 seconds for monitor to stop");
                    sleep(1);
                }
                if (!entered)
                {
                    pthread_mutex_unlock(&running_lock);
                    entered = 0;
                }
                pthread_mutex_lock(&running_lock);
                if (ctx->running)
                {
                    printf("Monitor thread has not stopped, but going to start another one anyway");
                }
                pthread_mutex_unlock(&running_lock);
                start_monitor(ctx, "");
            }
            else
            {
                if (current_time_millis() - ctx->last_heartbeat_sent_time > HEARTBEAT_INVERVAL_MILLIS)
                {
                    unsigned long olen = 0;
                    const unsigned long recvlen = 1024;
                    unsigned char *recv = (unsigned char *)malloc(sizeof(unsigned char) * recvlen);
                    memset(recv, 0, sizeof(unsigned char) * recvlen);

                    atclient_connection_send(&(ctx->monitor_connection), "noop:0", strlen("noop:0"), recv, recvlen, &olen);
                    free(recv);

                    ctx->last_heartbeat_sent_time = current_time_millis();
                }
            }
        }
        else
        {
            pthread_mutex_unlock(&should_be_running_lock);
        }
        sleep(5);
    }
}
