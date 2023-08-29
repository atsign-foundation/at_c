
#include "constants.h"

extern void wifi_connect(const char *ssid, const char *password);

void app_main(void)
{
    wifi_connect(CONFIG_ESP_WIFI_SSID, CONFIG_ESP_WIFI_PASSWORD);
}