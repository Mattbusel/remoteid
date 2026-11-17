/* Runs jjshoots/RemoteIDSpoofer (ESP8266 build) on a Linux host and writes
 * the Wi-Fi Beacon frames it would transmit to a pcap file. Nothing is
 * transmitted.
 *
 * Replaced: the ESP8266 platform file (id_open_esp8266.cpp) and the web
 * frontend. This file carries the platform functions with the same bytes
 * as id_open_esp8266.cpp (capability, rates, the Espressif element), and
 * the setup()/loop() of RemoteIDSpoofer.ino with fixed form inputs.
 * Time is virtual: millis() advances only through delay(), and the wall
 * clock follows settimeofday() exactly as on the board. rand() is the host
 * C library's, so the random identifiers differ from a real board's but
 * are made the same way.
 *
 * Usage: harness <out.pcap> <drones> <latitude> <longitude> <seconds>
 */
#include <Arduino.h>

#include "id_open.h"
#include "spoofer.h"

HardwareSerial Serial;

static const double START_UNIX = 1794916800.0; /* 2026-11-17 12:00:00 UTC */
static uint32_t virt_ms = 0;
static double wall_base = 0.0;    /* wall clock seconds at virt_ms == 0 */
static FILE *pcap = NULL;

extern "C" uint32_t millis(void) { return virt_ms; }
extern "C" void delay(uint32_t ms) { virt_ms += ms; }

extern "C" int shim_settimeofday(const struct timeval *tv, const struct timezone *) {
  wall_base = (double)tv->tv_sec + tv->tv_usec * 1e-6 - virt_ms / 1000.0;
  return 0;
}

extern "C" time_t shim_time(time_t *t) {
  time_t v = (time_t)(wall_base + virt_ms / 1000.0);
  if (t) *t = v;
  return v;
}

extern "C" int shim_clock_gettime(clockid_t, struct timespec *ts) {
  double v = wall_base + virt_ms / 1000.0;
  ts->tv_sec = (time_t)v;
  ts->tv_nsec = (long)((v - (double)ts->tv_sec) * 1e9);
  return 0;
}

/* --- id_open_esp8266.cpp equivalents ----------------------------------- */

void construct2() {}

void init2(char *, int, uint8_t *, uint8_t) {}

uint8_t *capability() {
  static uint8_t capa[2] = {0x11, 0x00};
  return capa;
}

int tag_rates(uint8_t *f, int o) {
  const uint8_t t[] = {0x01, 0x08, 0x8b, 0x96, 0x82, 0x84, 0x0c, 0x18, 0x30, 0x60};
  memcpy(f + o, t, sizeof t);
  return o + (int)sizeof t;
}

int tag_ext_rates(uint8_t *f, int o) {
  const uint8_t t[] = {0x32, 0x04, 0x6c, 0x12, 0x24, 0x48};
  memcpy(f + o, t, sizeof t);
  return o + (int)sizeof t;
}

int misc_tags(uint8_t *f, int o) {
  const uint8_t t[] = {0xdd, 0x09, 0x18, 0xfe, 0x34, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00};
  memcpy(f + o, t, sizeof t);
  return o + (int)sizeof t;
}

int transmit_wifi2(uint8_t *buffer, int length) {
  if (length > 0 && pcap) {
    double t = START_UNIX + virt_ms / 1000.0;
    uint32_t hdr[4] = {(uint32_t)t, (uint32_t)((t - (uint32_t)t) * 1e6 + 0.5), (uint32_t)length,
                       (uint32_t)length};
    fwrite(hdr, 4, 4, pcap);
    fwrite(buffer, 1, length, pcap);
  }
  return 0;
}

int transmit_ble2(uint8_t *, int) { return 0; }

/* --- RemoteIDSpoofer.ino with fixed frontend inputs --------------------- */

int num_spoofers = 0;
Spoofer spoofers[16];

int main(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: harness out.pcap drones lat lon seconds\n");
    return 2;
  }
  pcap = fopen(argv[1], "wb");
  uint32_t ghdr[6] = {0xA1B2C3D4, 0x00040002, 0, 0, 65535, 105 /* IEEE 802.11 */};
  fwrite(ghdr, 4, 6, pcap);
  num_spoofers = atoi(argv[2]);
  float lat = (float)atof(argv[3]);
  float lon = (float)atof(argv[4]);
  uint32_t end_ms = (uint32_t)(atof(argv[5]) * 1000.0);

  /* setup(): the web form would take up to two minutes; start at once. */
  for (int i = 0; i < num_spoofers; i++) {
    spoofers[i].init();
    spoofers[i].updateLocation(lat, lon);
  }
  /* loop() */
  while (virt_ms < end_ms) {
    for (int i = 0; i < num_spoofers; i++) {
      spoofers[i].update();
      delay(200 / num_spoofers);
    }
  }
  fclose(pcap);
  printf("jjshoots: %d drones, %.1f s\n", num_spoofers, virt_ms / 1000.0);
  return 0;
}
