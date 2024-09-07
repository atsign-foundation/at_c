#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include <atclient/atclient.h>
#include <atclient/atkeys.h>
#include <atlogger/atlogger.h>
#include <esp_spiffs.h>
#include <string.h>
#include "constants.h"

#define PATH "/storage/soccer99_key.atKeys"
#define WIFI_CONNECTED_BIT BIT0
#define TAG "pkam_authenticate"

static EventGroupHandle_t wifi_event_group;

/* Event handler for Wi-Fi events */
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Retrying to connect to the AP\n");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        if (event != NULL) {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&event->ip_info.ip));
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Got IP: %s\n", ip_str);
            xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        } else {
            atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Error: event data is NULL\n");
        }
    }
}

/* Structure to pass to the task */
typedef struct {
    atclient *client;
    atclient_atkeys *keys;
} pkam_authenticate_params_t;

/* Task for PKAM authentication */
static void pkam_authenticate_task(void *pvParameters) {
    pkam_authenticate_params_t *params = (pkam_authenticate_params_t *)pvParameters;

    // Ensure parameters are not NULL
    if (params == NULL || params->client == NULL || params->keys == NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Invalid parameters for PKAM authentication task\n");
        vTaskDelete(NULL);
        return;
    }

    // Add debug log for client and keys
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "PKAM task started: client=%p, keys=%p\n", params->client, params->keys);

    // Perform authentication
    if (atclient_pkam_authenticate(params->client, "@soccer99", params->keys, NULL) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to authenticate with secondary server\n");
    } else {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Successfully authenticated with secondary server\n");
    }

    // Notify the calling task that this task has finished
    xTaskNotifyGive(xTaskGetCurrentTaskHandle());

    free(params);  // Free the allocated structure after task completion
    vTaskDelete(NULL);
}

static int read_key_file(char **file_content) {
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/storage", .partition_label = NULL, .max_files = 5, .format_if_mount_failed = false
    };
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Failed to mount or format filesystem: %s\n", esp_err_to_name(ret));
        return 1;
    }

    FILE *f = fopen(PATH, "r");
    if (f == NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Failed to open key file for reading\n");
        esp_vfs_spiffs_unregister(NULL);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    *file_content = (char *)malloc(sizeof(char) * (file_size + 1));
    if (*file_content == NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for key file content\n");
        fclose(f);
        esp_vfs_spiffs_unregister(NULL);
        return 1;
    }

    size_t read_size = fread(*file_content, 1, file_size, f);
    if (read_size != file_size) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to read entire file\n");
        free(*file_content);
        *file_content = NULL;
        fclose(f);
        esp_vfs_spiffs_unregister(NULL);
        return 1;
    }
    (*file_content)[file_size] = '\0';

    fclose(f);
    esp_vfs_spiffs_unregister(NULL);
    return 0;
}

void wifi_init_sta() {
    wifi_event_group = xEventGroupCreate();

    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Wi-Fi initialization finished.\n");

    xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Wi-Fi Connected! Proceeding with code execution.\n");
}

void app_main(void) {
    atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

    atclient *atclient1 = NULL;
    atclient_atkeys *atkeys1 = NULL;

    // Dynamically allocate memory for atclient1
    atclient1 = (atclient *)malloc(sizeof(atclient));
    if (atclient1 == NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for atclient1\n");
        goto exit;
    }
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Initializing atclient1\n");
    atclient_init(atclient1);

    atkeys1 = (atclient_atkeys *)malloc(sizeof(atclient_atkeys));
    if (atkeys1 == NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for atkeys1\n");
        goto exit;
    }
    atclient_atkeys_init(atkeys1);

    char *key_file_content = NULL;
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
        if (ret != ESP_OK) goto exit;
    }

    wifi_init_sta();

    ret = read_key_file(&key_file_content);
    if (key_file_content != NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "Key file content: %.10s\n", key_file_content);
    } else {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Key file content is NULL\n");
        goto exit;
    }

    if ((ret = atclient_atkeys_populate_from_string(atkeys1, key_file_content)) != 0) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to populate atkeys from string: %d\n", ret);
        goto exit;
    }

    // Allocate and populate the structure to pass to the task
    pkam_authenticate_params_t *params = (pkam_authenticate_params_t *)malloc(sizeof(pkam_authenticate_params_t));
    if (params == NULL) {
        atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "Failed to allocate memory for task parameters\n");
        goto exit;
    }
    params->client = atclient1;
    params->keys = atkeys1;

    // Add debug logging for the task parameters
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "Creating PKAM authentication task\n");

    // Create the task for PKAM authentication
    xTaskCreate(&pkam_authenticate_task, "pkam_authenticate_task", 1024*32, params, 5, NULL);

    // Block and wait for the PKAM task to finish
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "PKAM authentication task completed\n");

exit: {
    free(key_file_content);
    free(atclient1);  // Free dynamically allocated memory for atclient1
    free(atkeys1);     // Free dynamically allocated memory for atkeys1
    nvs_flash_deinit();
}
}
