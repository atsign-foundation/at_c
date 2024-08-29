idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS ""
    REQUIRES atclient esp_wifi nvs_flash
    EMBED_FILES "assets/keys/@soccer99_key.atKeys"
)
