#include <string.h>
#include <esp_netif.h> //
#include <esp_event.h>
#include <esp_wifi.h>
#include <esp_log.h> // ESP_LOGI and ESP
#include <esp_wifi_types.h>
#include <nvs_flash.h> // NVS "non-volatile storage" (ROM)
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

static const char *TAG = "repl_esp32"; // for logging

extern void event_handler_wifi(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

extern void event_handler_ip(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

static int init_nvs()
{
    int ret = 1;
    // intialize NVS "non-volatile storage" (ROM)
    ret = nvs_flash_init(); // from nvs_flash.h

    // if NVS is not initialized, erase it and try again
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        // erase NVS
        ESP_ERROR_CHECK(nvs_flash_erase());
        // re-initialize NVS
        ret = nvs_flash_init();
    }

    return ret;
}

static int init_net()
{
    int ret = 1;

    // initialize underlying TCP/IP stack, esp_netif.h
    ESP_LOGI(TAG, "Initializing TCP/IP stack...");
    ret = esp_netif_init();
    ESP_ERROR_CHECK(ret);

    return ret;
}

static int init_event_handlers(EventGroupHandle_t *wifi_event_group)
{
    int ret = 1;

    // create default event loop, esp_event.h
    ESP_LOGI(TAG, "Creating default event loop...");
    ret = esp_event_loop_create_default();
    ESP_ERROR_CHECK(ret);

    // create default network interface, esp_wifi.h
    esp_netif_create_default_wifi_sta();

    // register wifi event handler, esp_event.h
    esp_event_base_t wifi_event_base = WIFI_EVENT;
    int32_t any_event_id = ESP_EVENT_ANY_ID;
    ret = esp_event_handler_instance_register(
        wifi_event_base,     // esp_event_base_t
        any_event_id,        // int32_t
        &event_handler_wifi, // esp_event_handler_t
        wifi_event_group,   // void * (event_handler_arg)
        NULL                 // esp_event_handler_instance_t * (instance)
    );
    ESP_ERROR_CHECK(ret);

    // register ip event handler, esp_event.h
    esp_event_base_t ip_event_base = IP_EVENT;
    ret = esp_event_handler_instance_register(
        ip_event_base,     // esp_event_base_t
        any_event_id,      // int32_t
        &event_handler_ip, // esp_event_handler_t
        NULL,              // void * (event_handler_arg)
        NULL               // esp_event_handler_instance_t * (instance)
    );

    return ret;
}

static int init_wifi_sta(const unsigned char *wifi_ssid, const unsigned long wifi_ssidlen, const unsigned char *wifi_password, const unsigned long wifi_passwordlen)
{
    int ret = 1;

    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();

    wifi_sta_config_t wifi_sta_config;
    memset(&wifi_sta_config, 0, sizeof(wifi_sta_config));
    memcpy(wifi_sta_config.ssid, wifi_ssid, wifi_ssidlen);
    memcpy(wifi_sta_config.password, wifi_password, wifi_passwordlen);

    wifi_config_t wifi_config = {
        .sta = wifi_sta_config};

    // init wifi
    ret = esp_wifi_init(&wifi_init_config);
    ESP_ERROR_CHECK(ret);

    // set mode to station
    ret = esp_wifi_set_mode(WIFI_MODE_STA);
    ESP_ERROR_CHECK(ret);

    // configure wifi
    ret = esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
    ESP_ERROR_CHECK(ret);

    // start wifi
    ret = esp_wifi_start();
    ESP_ERROR_CHECK(ret);

    return ret;
}

void wifi_connect(const char *ssid, const char *password)
{
    int ret = 1;

    // initialize NVS "non-volatile storage" (ROM), nvs_flash.h
    ESP_LOGI(TAG, "Initializing NVS...");
    ret = init_nvs();
    ESP_ERROR_CHECK(ret);

    // initialie network interface, esp_netif.h
    ESP_LOGI(TAG, "Initializing network interface...");
    ret = init_net();
    ESP_ERROR_CHECK(ret);

    // use free rtos to create event group, freertos/FreeRTOS.h
    EventGroupHandle_t wifi_event_group = xEventGroupCreate();

    // initialize event handlers, esp_event.h
    ESP_LOGI(TAG, "Initializing event handlers...");
    ret = init_event_handlers(&wifi_event_group);
    ESP_ERROR_CHECK(ret);

    // initialize wifi, esp_wifi.h
    ESP_LOGI(TAG, "Initializing wifi...");
    ret = init_wifi_sta((const unsigned char *) ssid, strlen(ssid), (const unsigned char *)password, strlen(password));
    ESP_ERROR_CHECK(ret);

    // event handler sets bits in event group, attempt connect using esp_wifi_connect()
    EventBits_t bits;
    do
    {
        ESP_LOGI(TAG, "Attempting to connect to WiFi...");
        ret = esp_wifi_connect();
        ESP_LOGI(TAG, "esp_wifi_connect() returned %d", (int) ret);
        vTaskDelay(1000 / portTICK_PERIOD_MS);

        bits = xEventGroupWaitBits(
            wifi_event_group,                   // EventGroupHandle_t
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, // bits to wait for
            pdFALSE,                            // clear bits on exit
            pdFALSE,                            // wait for all bits
            portMAX_DELAY                       // wait forever
        );
        if (bits & WIFI_CONNECTED_BIT)
        {
            ESP_LOGI(TAG, "Connected to WiFi !");
        }
        else if (bits & WIFI_FAIL_BIT)
        {
            ESP_LOGI(TAG, "Failed to connect to WiFi.");
        }
    } while (ret != ESP_OK);
}