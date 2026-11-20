// Feeds the 802.11 frames of a pcap file to an ESP32 scanner firmware's
// promiscuous callback, compiled for the host against shim/. Usage:
//   harness CAPTURE
// Radiotap (link type 127) is stripped; each frame gets 4 zero FCS bytes,
// because the ESP32 reports sig_len with the FCS included. Anything the
// firmware prints on its USB serial port goes to stdout.
#include "shim/esp32_shim.h"
#include <vector>
#include <deque>

void callback(void *, wifi_promiscuous_pkt_type_t);


HardwareSerial Serial(true);
HardwareSerial Serial1(false);
WiFiClass WiFi;
static BLEScan the_scan;
BLEScan *BLEDevice::getScan() { return &the_scan; }

static unsigned long now_ms = 0;
extern "C" unsigned long millis(void) { return now_ms; }
extern "C" unsigned long micros(void) { return now_ms * 1000; }
extern "C" void delay(unsigned long) {}
extern "C" int64_t esp_timer_get_time(void) { return (int64_t)now_ms * 1000; }

struct shim_queue { size_t size; std::deque<std::vector<uint8_t>> items; };
static std::vector<shim_queue *> all_queues;
extern "C" QueueHandle_t xQueueCreate(UBaseType_t, UBaseType_t item_size) {
    all_queues.push_back(new shim_queue{item_size, {}});
    return all_queues.back();
}
extern "C" BaseType_t xQueueSend(QueueHandle_t q, const void *item, TickType_t) {
    const uint8_t *p = (const uint8_t *)item;
    q->items.emplace_back(p, p + q->size);
    return pdTRUE;
}
extern "C" BaseType_t xQueueSendFromISR(QueueHandle_t q, const void *item, BaseType_t *woken) {
    if (woken) *woken = pdFALSE;
    return xQueueSend(q, item, 0);
}
extern "C" BaseType_t xQueueReceive(QueueHandle_t q, void *item, TickType_t) {
    if (q->items.empty()) return pdFALSE;
    memcpy(item, q->items.front().data(), q->size);
    q->items.pop_front();
    return pdTRUE;
}
void fw_setup();
// Per firmware: what its printer task does with one queued item.
extern "C" void shim_sink(const void *item);
static void shim_drain() {
    for (shim_queue *q : all_queues)
        while (!q->items.empty()) {
            std::vector<uint8_t> it = q->items.front();
            q->items.pop_front();
            shim_sink(it.data());
        }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: harness CAPTURE\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    std::vector<uint8_t> b;
    uint8_t chunk[65536];
    size_t n;
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) b.insert(b.end(), chunk, chunk + n);
    fclose(f);
    if (b.size() < 24 || b[0] != 0xd4 || b[1] != 0xc3) { fprintf(stderr, "need a little endian pcap\n"); return 2; }
    uint32_t lt; memcpy(&lt, &b[20], 4);
    size_t off = 24;
    uint64_t t0 = 0;
    fw_setup();  // the firmware's own setup(): creates its queues, prints its banner to stdout
    while (off + 16 <= b.size()) {
        uint32_t s, us, cl;
        memcpy(&s, &b[off], 4); memcpy(&us, &b[off + 4], 4); memcpy(&cl, &b[off + 8], 4);
        off += 16;
        if (off + cl > b.size()) break;
        const uint8_t *d = &b[off];
        size_t len = cl;
        off += cl;
        uint64_t t = (uint64_t)s * 1000 + us / 1000;
        if (!t0) t0 = t;
        now_ms = (unsigned long)(t - t0) + 1000;
        if (lt == 127) {
            if (len < 4) continue;
            size_t h = d[2] | (d[3] << 8);
            if (h > len) continue;
            d += h; len -= h;
        } else if (lt != 105) {
            continue;
        }
        if (len < 24 || len + 4 > 4095) continue;
        std::vector<uint8_t> buf(sizeof(wifi_promiscuous_pkt_t) + len + 4 + 64, 0);
        wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf.data();
        pkt->rx_ctrl.rssi = -50;
        pkt->rx_ctrl.sig_len = len + 4;
        pkt->rx_ctrl.channel = 6;
        memcpy(pkt->payload, d, len);
        callback(pkt, WIFI_PKT_MGMT);
        shim_drain();
    }
    fflush(stdout);
    return 0;
}
