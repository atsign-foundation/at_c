idf_component_register(
    SRCS "main.c" "event_handlers.c" "wifi.c"
    INCLUDE_DIRS "."
    REQUIRES atclient atchops mbedtls esp_wifi esp_event nvs_flash freertos
)
