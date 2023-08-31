#include <string.h>
#include <stdlib.h>
#include <esp_log.h>
#include <atclient/connection.h>

static const char *TAG = "repl_esp32 main";

extern int wifi_connect(const char *ssid, const char *password);

void app_main(void)
{
    int ret = 1;

    ret = wifi_connect(CONFIG_ESP_WIFI_SSID, CONFIG_ESP_WIFI_PASSWORD);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Failed to connect to WiFi.");
        goto exit;
    }
    ESP_LOGI(TAG, "Connected to WiFi.");

    ESP_LOGI(TAG, "Connecting to root.atsign.org:64...");
    atclient_connection_ctx root_connection;
    atclient_connection_init(&root_connection);
    ret = atclient_connection_connect(&root_connection, "root.atsign.org", 64);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Failed to connect to root.atsign.org. at_client_connection_connect: %d", ret);

        ESP_LOGI(TAG, "Trying again...");
        ret = atclient_connection_connect(&root_connection, "root.atsign.org", 64);
        if (ret != 0)
        {
            ESP_LOGE(TAG, "Failed to connect to root.atsign.org. at_client_connection_connect: %d", ret);
            goto exit;
        }
    }
    ESP_LOGI(TAG, "Connected to root.atsign.org");

    ESP_LOGI(TAG, "Sending data...");
    const unsigned long recvlen = 4096;
    unsigned char *recv = malloc(sizeof(unsigned char) * recvlen);
    unsigned long olen = 0;
    const char *src = "colin\r\n";
    const unsigned long srclen = strlen(src);

    ret = atclient_connection_send(&root_connection, recv, recvlen, &olen, (const unsigned char *) src, srclen);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Failed to send data. at_client_connection_send: %d", ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Receiving data...");
    ESP_LOGI(TAG, "olen: %lu", olen);
    ESP_LOGI(TAG, "recv: \"%s\"", recv);

    free(recv);
    goto exit;
exit:
{
    return;
}
}