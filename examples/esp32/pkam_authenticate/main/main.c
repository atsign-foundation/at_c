#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

/* esp_wifi component */
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"

/* nvs_flash component */
#include "nvs_flash.h"

/* atclient component */
#include <atclient/atclient.h>
#include <atlogger/atlogger.h>

#include <string.h>
#include <esp_spiffs.h>

#include "constants.h"

#define PATH "/spiffs/assets/keys/@soccer99_key.atKeys"

/* Event group for Wi-Fi events */
static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;

#define TAG "pkam_authenticate"

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
    esp_wifi_connect();
    ESP_LOGI(TAG, "retrying to connect to the AP");
  } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG, "got IP: " IPSTR, IP2STR(&event->ip_info.ip));
  }
}

static char* read_key_file() {
    // Initialize SPIFFS
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount or format filesystem: %s", esp_err_to_name(ret));
        return NULL;
    }

    // Open the key file for reading
    FILE* f = fopen(PATH, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open key file for reading");
        esp_vfs_spiffs_unregister(NULL);
        return NULL;
    }

    // Get the file size
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Allocate memory to hold the file content
    char* file_string = malloc(file_size + 1);
    if (file_string == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for key file content");
        fclose(f);
        esp_vfs_spiffs_unregister(NULL);
        return NULL;
    }

    // Read the file content into the allocated buffer
    fread(file_string, 1, file_size, f);
    file_string[file_size] = '\0'; // Null-terminate the string

    // Close the file and unmount SPIFFS
    fclose(f);
    esp_vfs_spiffs_unregister(NULL);

    return file_string;
}

void wifi_init_sta() {
  wifi_event_group = xEventGroupCreate();

  esp_netif_init();
  esp_event_loop_create_default();
  esp_netif_create_default_wifi_sta();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);

  esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);
  esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL);

  wifi_config_t wifi_config = {
      .sta =
          {
              .ssid = WIFI_SSID,
              .password = WIFI_PASS,
          },
  };
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
  esp_wifi_start();

  ESP_LOGI(TAG, "wifi_init_sta finished.");

  xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
}

void app_main(void) {
  // esp_err_t ret = nvs_flash_init();
  // if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
  //   ESP_ERROR_CHECK(nvs_flash_erase());
  //   ret = nvs_flash_init();
  // }
  // ESP_ERROR_CHECK(ret);

  // wifi_init_sta();

  char *key_file_content = read_key_file();

  if(key_file_content == NULL) {
    ESP_LOGE(TAG, "Failed to read key file");
    goto exit;
  }

//   atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_INFO, "key file content: %s\n", key_file_content);

//   atclient atclient1;
//   atclient_init(&atclient1);

//   atclient_atkeys atkeys;
//   atclient_atkeys_init(&atkeys);

//   if ((ret = atclient_atkeys_populate_from_string(&atkeys, key_file_content)) != 0) {
//     ESP_LOGE(TAG, "atclient_atkeys_populate_from_path: %d\n", ret);
//     goto exit;
//   }

exit: {
  free(key_file_content);
//   atclient_free(&atclient1);
//   atclient_atkeys_free(&atkeys);
}
}
