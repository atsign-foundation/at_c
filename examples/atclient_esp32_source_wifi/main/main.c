#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <nvs_flash.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <esp_log.h>
#include <esp_event.h>
#include <esp_wifi_types.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <esp_crt_bundle.h>
#include "atclient/connection.h"

static const char *TAG = "atclient_esp32_source_wifi";

static void event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    ESP_LOGI("WiFi event", "event_id: %d", (int)event_id);
}

static int init_event_handlers()
{
    int ret = 1;

    ret = esp_event_loop_create_default();
    if (ret != 0)
    {
        goto exit;
    }

    esp_netif_create_default_wifi_sta(); // create default WiFi station and attaches them to default event loop, this func aborts program if fails

    // listen for any WiFi events
    ret = esp_event_handler_instance_register(
        WIFI_EVENT,       // event_base_t from esp_event_base.h, in this case, event base is WIFI_EVENT
        ESP_EVENT_ANY_ID, // int32_t event_id from esp_event_base.h, in this case, we will handle all events
        &event_handler,   // esp_event_handler_t from esp_event_base.h
        NULL,             // args to event_handler
        NULL              // handler_instance to be used in esp_event_handler_instance_unregister
    );
    if (ret != 0)
    {
        goto exit;
    }

    // listen for any IP events
    ret = esp_event_handler_instance_register(
        IP_EVENT,
        ESP_EVENT_ANY_ID,
        &event_handler,
        NULL,
        NULL);
    if (ret != 0)
    {
        goto exit;
    }

    goto exit;

exit:
{
    return ret;
}
}

void app_main(void)
{
    int ret = 1;

    init_event_handlers(); // log any WIFI events

    ret = esp_netif_init(); // initialize underlying TCP/IP stack
    ESP_ERROR_CHECK(ret);

    wifi_init_config_t wifi_init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_config_t wifi_cfg = {
        .sta = {
            .ssid = "Jeremy",
            .password = "maya1234"}};

    ret = nvs_flash_init(); // initialize ROM - "non-volatile storage"
    ESP_ERROR_CHECK(ret);

    // initialize wifi, requires nvs_flash_init() to be called before
    ret = esp_wifi_init(&wifi_init_cfg);
    ESP_ERROR_CHECK(ret);

    ret = esp_wifi_set_mode(WIFI_MODE_STA); // set wifi mode to station
    ESP_ERROR_CHECK(ret);

    // set wifi configuration
    ret = esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_cfg);
    ESP_ERROR_CHECK(ret);

    // start wifi
    ret = esp_wifi_start();
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "Starting to connect to WiFi...");
    ret = esp_wifi_connect();
    while (ret != ESP_OK)
    {
        ESP_LOGI(TAG, "esp_wifi_connect() returned %d", ret);
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        ret = esp_wifi_connect();
    }
    ESP_LOGI(TAG, "Connected to WiFi! SSID: %s", wifi_cfg.sta.ssid);

    // =========
    // connect to root
    // =========

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Attaching the certificate bundle...");



    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)ROOT_CERT, strlen(ROOT_CERT) + 1);
    ESP_LOGI(TAG, "mbedtls_x509_crt_parse returned %d", ret);

    ret = esp_crt_bundle_attach(&conf);
    if (ret < 0)
    {
        ESP_LOGE(TAG, "esp_crt_bundle_attach returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

    /* Hostname set here should match CN in server certificate */
    if ((ret = mbedtls_ssl_set_hostname(&ssl, HOST)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x", -ret);
    }

    // initialize buf and flags
    char buf[2048];
    int flags;
    size_t len = 0;

    const char *HOSTSTR = HOST;
    const char *PORTSTR = "64";

    // wait
    vTaskDelay(25*1000 / portTICK_PERIOD_MS);

    mbedtls_net_init(&server_fd);

    ESP_LOGI(TAG, "Connecting to %s:%s...", HOST, PORTSTR);

    if ((ret = mbedtls_net_connect(&server_fd, HOST, PORTSTR, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
    }

    ESP_LOGI(TAG, "Connected.");

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
        }
    }

    // ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

    // if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
    // {
    //     /* In real life, we probably want to close connection if ret != 0 */
    //     ESP_LOGW(TAG, "Failed to verify peer certificate!");
    //     bzero(buf, sizeof(buf));
    //     mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
    //     ESP_LOGW(TAG, "verification info: %s", buf);
    // }
    // else
    // {
    //     ESP_LOGI(TAG, "Certificate verified.");
    // }

    // ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));

    ESP_LOGI(TAG, "Writing HTTP request...");
    mbedtls_ssl_handshake(&ssl);
}