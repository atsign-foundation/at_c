idf_component_register(
    SRCS "main.c"
    REQUIRES mbedtls atclient atchops esp_wifi nvs_flash
)