#include <stdio.h>
#include <atclient/atclient.h>
#include "esp_flash.h"
#include "esp_log.h"
#include "esp_ota_ops.h"        // Include for esp_ota_get_running_partition
#include "esp_partition.h"      // Include for esp_partition_t
#include <inttypes.h>           // Include for PRIu32 macro

void app_main(void) {
    printf("Yoo\n");

    // Get the total flash size
    uint32_t flash_size = 0;
    esp_err_t result = esp_flash_get_size(NULL, &flash_size);  // Get total flash size

    if (result == ESP_OK) {
        ESP_LOGI("Flash", "Total flash size: %" PRIu32 " bytes", flash_size);
    } else {
        ESP_LOGE("Flash", "Failed to get total flash size");
        return;
    }

    // Get the size of the partition where the application is stored
    const esp_partition_t *running_partition = esp_ota_get_running_partition();
    if (running_partition != NULL) {
        ESP_LOGI("Flash", "App partition size: %" PRIu32 " bytes", running_partition->size);
        ESP_LOGI("Flash", "App partition address: 0x%" PRIx32, running_partition->address);
    } else {
        ESP_LOGE("Flash", "Failed to get running partition information");
        return;
    }

    // Example to show remaining space: Subtract the application partition size from the total flash
    // This is a rough estimate and might not reflect actual used space.
    uint32_t used_flash = running_partition->size; // Assuming all of the partition is used
    uint32_t available_flash = flash_size - used_flash;

    ESP_LOGI("Flash", "Estimated used flash size: %" PRIu32 " bytes", used_flash);
    ESP_LOGI("Flash", "Estimated available flash size: %" PRIu32 " bytes", available_flash);
}