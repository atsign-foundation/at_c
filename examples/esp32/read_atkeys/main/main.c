#include <stdio.h>
#include <stdlib.h>
#include <esp_spiffs.h>
#include <esp_log.h>

#define TAG "spiffs_read"
#define FILE_PATH "/storage/soccer99_key.atKeys"

void app_main(void) {
    // Initialize SPIFFS
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/storage",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = false
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return;
    }

    // Open the key file for reading
    FILE* f = fopen(FILE_PATH, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open key file for reading");
        esp_vfs_spiffs_unregister(NULL);
        return;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Allocate memory to hold the file content
    char* file_content = malloc(file_size + 1);
    if (file_content == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for key file content");
        fclose(f);
        esp_vfs_spiffs_unregister(NULL);
        return;
    }

    // Read the file content into memory
    size_t read_size = fread(file_content, 1, file_size, f);
    if (read_size != file_size) {
        ESP_LOGE(TAG, "Failed to read entire file");
        free(file_content);
        fclose(f);
        esp_vfs_spiffs_unregister(NULL);
        return;
    }
    file_content[file_size] = '\0'; // Null-terminate the string

    ESP_LOGI(TAG, "Key file content: %s", file_content);

    // Clean up
    fclose(f);
    free(file_content);
    esp_vfs_spiffs_unregister(NULL);
}
