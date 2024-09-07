idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "include"
    REQUIRES atclient esp_wifi nvs_flash spiffs
)
