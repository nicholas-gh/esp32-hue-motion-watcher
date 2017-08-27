/* HTTPS GET Example using plain mbedTLS sockets
 *
 * Contacts the howsmyssl.com API via TLS v1.2 and reads a JSON
 * response.
 *
 * Adapted from the ssl_client1 example in mbedtls.
 *
 * Original Copyright (C) 2006-2016, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD, Apache 2.0 License.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "mbedtls/platform.h"
#include "mbedtls/base64.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include "ssd1306.h"
#include "gpio_task_buzz.h"
#include "https_request_main.h"
#include "https_flash_lights.h"

#include "settings.h"

/* The examples use simple WiFi configuration that you can set via
   'make menuconfig'.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_WIFI_SSID CONFIG_WIFI_SSID
#define EXAMPLE_WIFI_PASS CONFIG_WIFI_PASSWORD

/* FreeRTOS event group to signal when we are connected & ready to make a request */
EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;


static const char *TAG = "main";

/* Root cert for howsmyssl.com, found in cert.c */
extern const char *server_root_cert;

#ifdef MBEDTLS_DEBUG_C

#define MBEDTLS_DEBUG_LEVEL 4

/* mbedtls debug function that translates mbedTLS debug output
   to ESP_LOGx debug output.

   MBEDTLS_DEBUG_LEVEL 4 means all mbedTLS debug output gets sent here,
   and then filtered to the ESP logging mechanism.
*/
static void mbedtls_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    const char *MBTAG = "mbedtls";
    char *file_sep;

    /* Shorten 'file' from the whole file path to just the filename

       This is a bit wasteful because the macros are compiled in with
       the full _FILE_ path in each case.
    */
    file_sep = rindex(file, '/');
    if(file_sep)
        file = file_sep+1;

    switch(level) {
    case 1:
        ESP_LOGI(MBTAG, "%s:%d %s", file, line, str);
        break;
    case 2:
    case 3:
        ESP_LOGD(MBTAG, "%s:%d %s", file, line, str);
    case 4:
        ESP_LOGV(MBTAG, "%s:%d %s", file, line, str);
        break;
    default:
        ESP_LOGE(MBTAG, "Unexpected log level %d: %s", level, str);
        break;
    }
}

#endif

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
	ssd1306_clear(0);
	ssd1306_select_font(0, 1);      
	ssd1306_draw_string(0, 10, 30, "Connecting...", 1, 0);
	ssd1306_refresh(0, true);
	
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
	ssd1306_clear(0);
	ssd1306_select_font(0, 1);      
	ssd1306_draw_string(0, 10, 30, "Connected...", 1, 0);
	ssd1306_refresh(0, true);
	
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

void initialise_wifi(void)
{
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_WIFI_SSID,
            .password = EXAMPLE_WIFI_PASS,
        },
    };
    ESP_LOGI(TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK( esp_wifi_start() );
}

static const char *REQUEST = "GET " HUE_WEB_URL " HTTP/1.0\r\n"
    "Host: "HUE_WEB_SERVER"\r\n"
    "User-Agent: esp-idf/1.0 esp32\r\n"
    "\r\n";

void hue_get_task(void *pvParameters)
{
    const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *res;
    struct in_addr *addr;
    int s, r;
    char recv_buf[1024];
    char lastupdated[19];

    bzero(lastupdated, sizeof(lastupdated));
    
    while(1) {
      vTaskDelay(1500 / portTICK_PERIOD_MS); // sleep 1500ms
    
    while(1) {
        /* Wait for the callback to set the CONNECTED_BIT in the
           event group.
        */
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                            false, true, portMAX_DELAY);
        ESP_LOGI(TAG, "Connected to AP");

        int err = getaddrinfo(HUE_WEB_SERVER, "80", &hints, &res);

        if(err != 0 || res == NULL) {
            ESP_LOGE(TAG, "DNS lookup failed err=%d res=%p", err, res);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }

        /* Code to print the resolved IP.

           Note: inet_ntoa is non-reentrant, look at ipaddr_ntoa_r for "real" code */
        addr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
        ESP_LOGI(TAG, "DNS lookup succeeded. IP=%s", inet_ntoa(*addr));

        s = socket(res->ai_family, res->ai_socktype, 0);
        if(s < 0) {
            ESP_LOGE(TAG, "... Failed to allocate socket.");
            freeaddrinfo(res);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }
        ESP_LOGI(TAG, "... allocated socket\r\n");

        if(connect(s, res->ai_addr, res->ai_addrlen) != 0) {
            ESP_LOGE(TAG, "... socket connect failed errno=%d", errno);
            close(s);
            freeaddrinfo(res);
            vTaskDelay(4000 / portTICK_PERIOD_MS);
            continue;
        }

        ESP_LOGI(TAG, "... connected");
        freeaddrinfo(res);

        if (write(s, REQUEST, strlen(REQUEST)) < 0) {
            ESP_LOGE(TAG, "... socket send failed");
            close(s);
            vTaskDelay(4000 / portTICK_PERIOD_MS);
            continue;
        }
        ESP_LOGI(TAG, "... socket send success");

        /* Read HTTP response */
	int offset = 0;
	bzero(recv_buf, sizeof(recv_buf));
        do {
            r = read(s, recv_buf+offset, sizeof(recv_buf)-offset-1);
	    offset += r;
        } while(r > 0);

	ESP_LOGI(TAG, "Got: %s", recv_buf);
	
	// "lastupdated":"2017-08-22T11:46:25"
	char *res = strstr(recv_buf, "\"lastupdated\":");
	if (res == NULL) {
	  ESP_LOGW(TAG, "lastupdated not found");
	} else {
	  ESP_LOGI(TAG, "found at %s", res);
	  res += 15;
	  res[sizeof(lastupdated)] = 0;
	  ESP_LOGI(TAG, "using %s", res);

	  if (lastupdated[0] != 0) {

	    int y,M,d,h,m,s;
	    struct tm lasttime, nowtime, currenttime;
	    time_t current;

	    char buf[50];

	    sscanf(lastupdated, "%d-%d-%dT%d:%d:%d", &y, &M, &d, &h, &m, &s);
	    lasttime.tm_year = y - 1900; // Year since 1900
	    lasttime.tm_mon = M - 1;     // 0-11
	    lasttime.tm_mday = d;        // 1-31
	    lasttime.tm_hour = h;        // 0-23
	    lasttime.tm_min = m;         // 0-59
	    lasttime.tm_sec = s;         // 0-61 (0-60 in C++11)
	    
	    sscanf(res, "%d-%d-%dT%d:%d:%d", &y, &M, &d, &h, &m, &s);
	    nowtime.tm_year = y - 1900; // Year since 1900
	    nowtime.tm_mon = M - 1;     // 0-11
	    nowtime.tm_mday = d;        // 1-31
	    nowtime.tm_hour = h;        // 0-23
	    nowtime.tm_min = m;         // 0-59
	    nowtime.tm_sec = s;         // 0-61 (0-60 in C++11)
	    
	    time(&current);	    
	    setenv("TZ", "UTC", 1);
	    tzset();
	    localtime_r(&current, &currenttime);

	    time_t t1 = mktime(&lasttime);
	    time_t t2 = mktime(&nowtime);
	    time_t t3 = mktime(&currenttime);	    
	    double diffSecs = difftime(t2, t1);
	    double ageSecs = difftime(t3, t1);
	    char strftime_buf[64];
	    
	    ssd1306_clear(0);      
	    ssd1306_select_font(0, 1);
	    ssd1306_draw_string(0, 0, 0, "Last activity in", 1, 0);
	    ssd1306_draw_string(0, 0, 10, "upstairs hallway:", 1, 0);
	    //ssd1306_select_font(0, 1);	    
	    sprintf(buf, "%02d:%02d   UTC", nowtime.tm_hour, nowtime.tm_min);
	    ssd1306_draw_string(0, 40, 30, buf, 1, 0);
	    //ssd1306_select_font(0, 0);
	    ssd1306_draw_hline(0, 0, 45, 200, 1);
	    strftime(strftime_buf, sizeof(strftime_buf), "%H:%M UTC", &currenttime);
	    ssd1306_draw_string(0, 0, 53, strftime_buf, 1, 0);

	    sprintf(buf, "%.0f min ago", (ageSecs / 60));
	    ssd1306_draw_string(0, 65, 53, buf, 1, 0);	    
	    
	    ssd1306_refresh(0, true);
	    
	    ESP_LOGI(TAG, "%f seconds since last one", diffSecs);
	    
	    if (!strncmp(lastupdated, res, sizeof(lastupdated))) {
	      ESP_LOGI(TAG, "Matches last time");
	    } else {
	      ESP_LOGI(TAG, "Different");
	      
	      if (diffSecs > (60*5)) {
		// segfaults ?
		//xTaskCreate(hue_flashlights_task, "hue_flashlights_task", 4096*2, NULL, 5, NULL);
		
		hue_flashlights_task(NULL);
		play_theme();
	      } else {
		
	      }
	    }
	  }
	  
	  // doesn't seem to do anything?
	  //strncpy(res, lastupdated, sizeof(lastupdated));
	  for (int i=0; i<sizeof(lastupdated);i++) {
	    lastupdated[i] = res[i];
	  }
	  lastupdated[sizeof(lastupdated)] = 0;
	  ESP_LOGI(TAG, "copied into %s", lastupdated);	  
	}

        ESP_LOGI(TAG, "... done reading from socket. Last read return=%d errno=%d\r\n", r, errno);
        close(s);

        for(int countdown = 2; countdown >= 0; countdown--) {
            ESP_LOGI(TAG, "%d... ", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
	
        ESP_LOGI(TAG, "Starting again!");
    }
    }
}

void https_get_task(void *pvParameters) {
    char buf[512];
    int ret, flags, len;

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
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the CA root certificate...");

    ret = mbedtls_x509_crt_parse(&cacert, (uint8_t*)server_root_cert, strlen(server_root_cert)+1);
    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

     /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.

       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef MBEDTLS_DEBUG_C
    mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LEVEL);
    mbedtls_ssl_conf_dbg(&conf, mbedtls_debug, NULL);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1) {
        /* Wait for the callback to set the CONNECTED_BIT in the
           event group.
        */
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                            false, true, portMAX_DELAY);
        ESP_LOGI(TAG, "Connected to AP");

        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER,
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        ESP_LOGI(TAG, "Connected.");

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        } else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Writing HTTP request...");


		 char tokenbuf[64];
		 char bodybuf[256];
		 char reqbuf[1024];

		 sprintf(tokenbuf,PUSHBULLET_TOKEN);
		 //sprintf(bodybuf,"{\"body\":\"Battery low on Device AB34IlK22\",\"title\":\"Message\",\"type\":\"note\"}");


		 sprintf(bodybuf,"{\"body\":\"Hello, playing music\",\"title\":\"Message\",\"type\":\"note\"}");      

		 sprintf(reqbuf,"POST /v2/pushes HTTP/1.1\r\nHost: api.pushbullet.com\r\nUser-Agent: ESP32\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAccess-Token: %s\nConnection: close\r\n\r\n%s",strlen(bodybuf),tokenbuf,bodybuf);

		 ESP_LOGI(TAG, "req=[%s]",reqbuf);

		while((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)reqbuf, strlen(reqbuf))) <= 0) {
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
				goto exit;
			}
		}

		len = ret;
		ESP_LOGI(TAG, "%d bytes written", len);
		ESP_LOGI(TAG, "Reading HTTP response...");

		do {
			len = sizeof(buf) - 1;
			bzero(buf, sizeof(buf));
			ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

			if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
				continue;
			}

			if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
				ret = 0;
				break;
			}

			if(ret < 0) {
				ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
				break;
			}

			if(ret == 0) {
				ESP_LOGI(TAG, "connection closed");
				break;
			}

			len = ret;
			ESP_LOGI(TAG, "%d bytes read", len);
			/* Print response directly to stdout as it is read */
			for(int i = 0; i < len; i++) {
				putchar(buf[i]);
			}
		} while(1);
         mbedtls_ssl_close_notify(&ssl);

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0)
        {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }

        for(int countdown = 36000; countdown >= 0; countdown--) {
        	if(countdown%10==0) {
        		ESP_LOGI(TAG, "%d...", countdown);
        	}
            vTaskDelay(1000 / portTICK_RATE_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
    }
}

