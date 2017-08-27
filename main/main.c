/* Copyright (c) 2017 pcbreflux. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>. *
 */
#include <string.h>
#include <stdlib.h>

#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/heap_regions.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_heap_alloc_caps.h"
#include "nvs_flash.h"

#include "apps/sntp/sntp.h"

#include "gpio_task_buzz.h"
#include "gpio_task_blink.h"
#include "https_request_main.h"
#include "https_flash_lights.h"

#include "esp_log.h"
#include "ssd1306.h"
#include "fonts.h"

#define TAG "MAIN"

static void obtain_time(void);
static void initialize_sntp(void);

static void obtain_time(void)
{
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                        false, true, portMAX_DELAY);
    initialize_sntp();

    // wait for time to be set
    time_t now = 0;
    struct tm timeinfo = { 0 };
    int retry = 0;
    const int retry_count = 10;
    while(timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count) {
        ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", retry, retry_count);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        time(&now);
        localtime_r(&now, &timeinfo);
    }
}

static void initialize_sntp(void)
{
    ESP_LOGI(TAG, "Initializing SNTP");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_init();
}

void app_main() {
    ESP_LOGI(TAG,"free DRAM %u IRAM %u",esp_get_free_heap_size(),xPortGetFreeHeapSizeTagged(MALLOC_CAP_32BIT));

    if (ssd1306_init(0, GPIO_NUM_4, GPIO_NUM_5)) {
      ESP_LOGI("OLED", "oled inited");
      ssd1306_clear(0);      
      ssd1306_select_font(0, 1);      
      ssd1306_draw_string(0, 10, 30, "Booting...", 1, 0);
      ssd1306_refresh(0, true);
    } else {
      ESP_LOGE("OLED", "oled init failed");
    }
	
    nvs_flash_init();
    initialise_wifi();

    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    // Is time set? If not, tm_year will be (1970 - 1900).
    if (timeinfo.tm_year < (2016 - 1900)) {
        obtain_time();
        // update 'now' variable with current time
        time(&now);
    }
    
    xTaskCreate(gpio_task_buzz, "gpio_task_buzz", 4096, NULL, 5, NULL);
    xTaskCreate(gpio_task_blink, "gpio_task_blink", 4096, NULL, 5, NULL);
    xTaskCreate(hue_get_task, "hue_get_task", 4096, NULL, 5, NULL);
  
    /*
      hue_flashlights_task(NULL);
      play_theme();
    */
    
}

