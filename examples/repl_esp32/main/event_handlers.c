#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_wifi_types.h>
#include <esp_netif_types.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

const char *TAG_WIFI_EVENT_HANDLER = "repl_esp32 Wifi Event Handler";
const char *TAG_IP_EVENT_HANDLER = "repl_esp32 IP Event Handler";

// arguments should be identical to esp_event_handler_t
void event_handler_wifi(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    // event_base should always be WIFI_EVENT
    if(event_base != WIFI_EVENT)
    {
        return;
    }

    EventGroupHandle_t wifi_event_group = *((EventGroupHandle_t *) event_handler_arg);

    if(event_id == WIFI_EVENT_STA_START)
    {
        ESP_LOGI(TAG_WIFI_EVENT_HANDLER, "Connecting to WiFi...");
    } else if(event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        ESP_LOGI(TAG_WIFI_EVENT_HANDLER, "Disconnected from WiFi...");
        xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT); // set fail bit
    } else if(event_id == WIFI_EVENT_STA_CONNECTED)
    {
        ESP_LOGI(TAG_WIFI_EVENT_HANDLER, "Connected to WiFi ! ... SSID:%s", ((wifi_event_sta_connected_t *) event_data)->ssid);
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT); // set connected bit
    }
}

// arguments should be identical to esp_event_handler_t
void event_handler_ip(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    // event_base should always be IP_EVENT, otherwise this function is being used incorrectly.
    if(event_base != IP_EVENT)
    {
        return;
    }

    if(event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG_IP_EVENT_HANDLER, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
    } else if(event_id == IP_EVENT_STA_LOST_IP)
    {
        ESP_LOGI(TAG_IP_EVENT_HANDLER, "Lost IP...");
    }
}