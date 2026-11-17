/* Minimal Arduino / ESP8266 shim so jjshoots/RemoteIDSpoofer builds on a
 * Linux host for corpus synthesis. Time comes from a virtual clock driven by
 * harness.cpp; frames go to a pcap file instead of a radio. */
#ifndef RID_CORPUS_ARDUINO_H
#define RID_CORPUS_ARDUINO_H

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif
uint32_t millis(void);
void delay(uint32_t ms);
int shim_settimeofday(const struct timeval *tv, const struct timezone *tz);
time_t shim_time(time_t *t);
int shim_clock_gettime(clockid_t clk, struct timespec *ts);
#ifdef __cplusplus
}
#endif

#define settimeofday(tv, tz) shim_settimeofday(tv, tz)
#define time(t) shim_time(t)
#define clock_gettime(c, ts) shim_clock_gettime(c, ts)

typedef uint8_t uint8;

#ifdef __cplusplus
#include <string>

template <typename A, typename B, typename C>
static inline A constrain(A x, B lo, C hi) {
  return x < lo ? (A)lo : (x > hi ? (A)hi : x);
}

class String {
 public:
  String() {}
  String(const char *s) : s_(s ? s : "") {}
  void concat(char c) { s_.push_back(c); }
  char operator[](unsigned i) const { return i < s_.size() ? s_[i] : 0; }
  unsigned length() const { return (unsigned)s_.size(); }
  const char *c_str() const { return s_.c_str(); }

 private:
  std::string s_;
};

class Stream {
 public:
  void print(const char *) {}
};

class HardwareSerial : public Stream {
 public:
  void begin(unsigned long) {}
  void println(const char *) {}
};

extern HardwareSerial Serial;
#endif

#endif
