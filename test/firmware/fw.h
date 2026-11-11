/*
 * Test firmware types and prototypes.
 *
 * This header is used twice:
 *   1. to build the firmware itself, and
 *   2. by test/ghidra_setup.py, which feeds it to Ghidra's C parser to
 *      simulate the "RE annotations" a human would have created in the
 *      Ghidra database for a raw, symbol-less firmware dump.
 *
 * Keep it parseable by Ghidra's CParser: no includes, no macros with
 * arguments, no GCC attributes.
 */

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef signed int int32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;

enum mode {
    MODE_FAULT = -1,
    MODE_IDLE = 0,
    MODE_RUN = 1,
    MODE_CALIBRATE = 7
};

struct point {
    int x;
    int y;
};

typedef int (*filter_fn)(int);

typedef struct sensor {
    char name[8];
    uint16_t id;
    uint8_t flags;
    uint8_t enabled : 1;
    uint8_t channel : 3;
    enum mode mode;
    struct point pos;
    int32_t history[4];
    uint32_t samples;
    struct sensor *next;
    filter_fn filter;
} sensor_t;

union value {
    uint32_t u;
    float f;
    uint8_t bytes[4];
};

struct stats {
    int64_t total;
    int min;
    int max;
    union value last;
};

/* Globals */
extern volatile uint32_t g_tick;
extern int g_counter;
extern sensor_t g_sensors[3];
extern sensor_t *g_sensor_list;
extern struct stats g_stats;
extern volatile int g_result[8];
extern const char g_banner[8];

/* Functions */
int clamp(int v, int lo, int hi);
int filter_double(int v);
int filter_offset(int v);
int fact(int n);
int sum_history(const sensor_t *s);
uint32_t checksum(const uint8_t *buf, uint32_t len);
int64_t mul64(int64_t a, int64_t b);
int many_args(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j);
float scale(float v, float k);
void sensor_update(sensor_t *s, int sample);
int process_all(sensor_t *list, int round);
void update_stats(struct stats *st, int v);
void fw_main(void);
void _cstart(void);
