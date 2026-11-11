/*
 * Test firmware for ghidra2dwarf-raw.
 *
 * Deterministic: every value the GDB test checks is derived from the
 * constants below. If you change anything here, update test/gdb_test.py.
 */
#include "fw.h"
#include "edge.h"

volatile uint32_t g_tick;
int g_counter = 5;
const char g_banner[8] = "fw-test";
struct stats g_stats;
volatile int g_result[8];

sensor_t g_sensors[3] = {
    { "temp", 0x101, 0x11, 1, 2, MODE_RUN,  { 10, 20 }, { 0 }, 0, &g_sensors[1], filter_double },
    { "press", 0x202, 0x22, 1, 5, MODE_IDLE, { -3, 4 }, { 0 }, 0, &g_sensors[2], filter_offset },
    { "volt", 0x303, 0x33, 0, 7, MODE_CALIBRATE, { 7, -7 }, { 0 }, 0, 0, 0 },
};
sensor_t *g_sensor_list = &g_sensors[0];

int clamp(int v, int lo, int hi)
{
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}

int filter_double(int v)
{
    return clamp(v * 2, -1000, 1000);
}

int filter_offset(int v)
{
    return v + 100;
}

int fact(int n)
{
    if (n <= 1)
        return 1;
    return n * fact(n - 1);
}

int sum_history(const sensor_t *s)
{
    int total = 0;
    int i;
    for (i = 0; i < 4; i++)
        total += s->history[i];
    return total;
}

uint32_t checksum(const uint8_t *buf, uint32_t len)
{
    uint32_t sum = 0x12345678;
    uint32_t i;
    for (i = 0; i < len; i++) {
        sum = (sum << 5) ^ (sum >> 27) ^ buf[i];
    }
    return sum;
}

int64_t mul64(int64_t a, int64_t b)
{
    return a * b + 1;
}

int many_args(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j)
{
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i + 10 * j;
}

float scale(float v, float k)
{
    return v * k + 0.5f;
}

void update_stats(struct stats *st, int v)
{
    st->total += v;
    if (v < st->min)
        st->min = v;
    if (v > st->max)
        st->max = v;
    st->last.f = scale((float)v, 0.25f);
}

void sensor_update(sensor_t *s, int sample)
{
    int filtered;
    int slot;

    if (s->filter)
        filtered = s->filter(sample);
    else
        filtered = sample;

    slot = s->samples & 3;
    s->history[slot] = filtered;
    s->samples++;
    s->pos.x += s->channel;
    update_stats(&g_stats, filtered);
}

int process_all(sensor_t *list, int round)
{
    sensor_t *s;
    int count = 0;

    for (s = list; s != 0; s = s->next) {
        if (!s->enabled)
            continue;
        sensor_update(s, round * 10 + s->id);
        count++;
    }
    return count;
}

void fw_main(void)
{
    int round;

    g_stats.min = 0x7fffffff;
    g_stats.max = -0x7fffffff;

    g_result[0] = fact(5);
    g_result[1] = (int)checksum((const uint8_t *)g_banner, 7);
    g_result[2] = (int)mul64(0x100000000LL, 3);
    g_result[3] = many_args(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);

    for (round = 0; round < 3; round++) {
        g_result[4] = process_all(g_sensor_list, round);
        g_counter++;
    }
    g_result[5] = sum_history(&g_sensors[0]);
    g_result[6] = g_counter;
    g_result[7] = 0x600d;

    for (;;)
        g_tick++;
}

extern uint32_t __data_load[], __data_start[], __data_end[];
extern uint32_t __bss_start[], __bss_end[];

void _cstart(void)
{
    uint32_t *src = __data_load;
    uint32_t *dst = __data_start;

    while (dst < __data_end)
        *dst++ = *src++;
    for (dst = __bss_start; dst < __bss_end; dst++)
        *dst = 0;
    edge_main();
    fw_main();
}
