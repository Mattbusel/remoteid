/* Host shim for ESP32 Arduino Remote ID scanner firmware: just enough of
 * the Arduino, ESP-IDF, FreeRTOS and BLE APIs for the firmware's own
 * main.cpp, wifi.c and opendroneid.c to compile on a PC, so its Wi-Fi
 * promiscuous callback can be fed frames from a capture file. Radio, task
 * and peripheral calls do nothing; Serial prints go to stdout. */
#ifndef ESP32_SHIM_H
#define ESP32_SHIM_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

typedef enum { WIFI_PKT_MGMT, WIFI_PKT_CTRL, WIFI_PKT_DATA, WIFI_PKT_MISC } wifi_promiscuous_pkt_type_t;
typedef struct {
    signed rssi : 8;
    unsigned sig_len : 12;
    unsigned channel : 4;
} wifi_pkt_rx_ctrl_t;
typedef struct {
    wifi_pkt_rx_ctrl_t rx_ctrl;
    uint8_t payload[0];
} wifi_promiscuous_pkt_t;

typedef int esp_err_t;
typedef const char *esp_event_base_t;
typedef int wifi_init_config_t;
typedef int BaseType_t;
typedef unsigned int UBaseType_t;
typedef uint32_t TickType_t;
typedef void *TaskHandle_t;
typedef struct shim_queue *QueueHandle_t;
typedef int portMUX_TYPE;
#define ESP_OK 0
#define pdFALSE 0
#define pdTRUE 1
#define pdPASS 1
#define portMAX_DELAY 0xffffffffu
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL_ISR(m) ((void)(m))
#define portEXIT_CRITICAL_ISR(m) ((void)(m))
#define portENTER_CRITICAL(m) ((void)(m))
#define portEXIT_CRITICAL(m) ((void)(m))
#define portYIELD_FROM_ISR() ((void)0)
#define pdMS_TO_TICKS(x) (x)
#define WIFI_INIT_CONFIG_DEFAULT() 0
#define WIFI_STORAGE_RAM 0
#define WIFI_MODE_NULL 0
#define WIFI_MODE_STA 1
#define WIFI_STA 1
#define WIFI_SECOND_CHAN_NONE 0
#define ESP_EVENT_ANY_BASE ((esp_event_base_t)0)
#define ESP_EVENT_ANY_ID (-1)
#define ESP_LOG_NONE 0
#define OUTPUT 1
#define INPUT 0
#define HIGH 1
#define LOW 0
#define SERIAL_8N1 0

#ifdef __cplusplus
extern "C" {
#endif
unsigned long millis(void);
unsigned long micros(void);
void delay(unsigned long ms);
static inline esp_err_t shim_ok(void) { return ESP_OK; }
#define esp_wifi_init(...) shim_ok()
#define esp_wifi_set_storage(...) shim_ok()
#define esp_wifi_set_mode(...) shim_ok()
#define esp_wifi_start(...) shim_ok()
#define esp_wifi_set_promiscuous(...) shim_ok()
#define esp_wifi_set_promiscuous_rx_cb(...) shim_ok()
#define esp_wifi_set_promiscuous_filter(...) shim_ok()
#define esp_wifi_set_channel(...) shim_ok()
#define esp_netif_init(...) shim_ok()
#define esp_event_loop_create_default(...) shim_ok()
#define esp_event_handler_instance_register(...) shim_ok()
#define esp_event_handler_register(...) shim_ok()
#define nvs_flash_init(...) shim_ok()
#define nvs_flash_erase(...) shim_ok()
#define esp_log_level_set(...) ((void)0)
#define setCpuFrequencyMhz(...) ((void)0)
#define pinMode(...) ((void)0)
#define digitalWrite(...) ((void)0)
#define tone(...) ((void)0)
#define noTone(...) ((void)0)
#define vTaskDelay(...) ((void)0)
#define vTaskDelete(...) ((void)0)
#define xTaskCreatePinnedToCore(...) pdPASS
#define xTaskCreate(...) pdPASS
int64_t esp_timer_get_time(void);
QueueHandle_t xQueueCreate(UBaseType_t len, UBaseType_t item_size);
BaseType_t xQueueSendFromISR(QueueHandle_t q, const void *item, BaseType_t *woken);
BaseType_t xQueueSend(QueueHandle_t q, const void *item, TickType_t wait);
BaseType_t xQueueReceive(QueueHandle_t q, void *item, TickType_t wait);
#ifdef __cplusplus
}

#include <string>
class String : public std::string {
public:
    String() {}
    String(const char *s) : std::string(s ? s : "") {}
    String(const std::string &s) : std::string(s) {}
    String(int v) : std::string(std::to_string(v)) {}
};

class HardwareSerial {
public:
    void begin(unsigned long, int = 0, int = -1, int = -1) {}
    int availableForWrite() { return 1 << 20; }
    int available() { return 0; }
    int read() { return -1; }
    void println(const char *s = "") { if (out) { fputs(s, stdout); fputc('\n', stdout); } }
    void println(const String &s) { println(s.c_str()); }
    void println(int v) { if (out) printf("%d\n", v); }
    void print(const char *s) { if (out) fputs(s, stdout); }
    void print(const String &s) { print(s.c_str()); }
    void print(int v) { if (out) printf("%d", v); }
    template <typename... A> void printf(const char *f, A... a) { if (out) ::printf(f, a...); }
    size_t write(const uint8_t *b, size_t n) { if (out) fwrite(b, 1, n, stdout); return n; }
    size_t write(uint8_t c) { if (out) fputc(c, stdout); return 1; }
    void flush() { fflush(stdout); }
    explicit operator bool() const { return true; }
    bool out;
    explicit HardwareSerial(bool o) : out(o) {}
};
extern HardwareSerial Serial;   /* USB serial: the JSON the host app reads */
extern HardwareSerial Serial1;  /* mesh UART: not printed */

class WiFiClass {
public:
    void mode(int) {}
    void disconnect() {}
};
extern WiFiClass WiFi;

class BLEAddress {
public:
    uint8_t a[6];
    uint8_t *getNative() { return a; }
    std::string toString() { return ""; }
};
class BLEAdvertisedDevice {
public:
    uint8_t *payload = nullptr;
    size_t len = 0;
    int rssi = 0;
    BLEAddress addr;
    size_t getPayloadLength() { return len; }
    uint8_t *getPayload() { return payload; }
    BLEAddress getAddress() { return addr; }
    int getRSSI() { return rssi; }
    bool haveServiceData() { return false; }
};
class BLEAdvertisedDeviceCallbacks {
public:
    virtual ~BLEAdvertisedDeviceCallbacks() {}
    virtual void onResult(BLEAdvertisedDevice) = 0;
};
class BLEScanResults {};
class BLEScan {
public:
    void setAdvertisedDeviceCallbacks(BLEAdvertisedDeviceCallbacks *c, bool = false, bool = false) { cb = c; }
    void setActiveScan(bool) {}
    void setInterval(int) {}
    void setWindow(int) {}
    BLEScanResults *start(int, bool = false) { return nullptr; }
    void clearResults() {}
    BLEAdvertisedDeviceCallbacks *cb = nullptr;
};
class BLEDevice {
public:
    static void init(const char *) {}
    static BLEScan *getScan();
};
#endif
#endif
