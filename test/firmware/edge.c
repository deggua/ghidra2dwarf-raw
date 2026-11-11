/*
 * Edge cases for the exporter. Runs before fw_main() (called from _cstart).
 * Expected values are asserted by test/gdb_edge_checks.py.
 */
#include <stdarg.h>
#include "fw.h"
#include "edge.h"

union value g_union;
short g_matrix[3][4] = { { 1, 2, 3, 4 }, { 5, 6, 7, 8 }, { 9, 10, 11, -12 } };
uint16_t g_msgbuf[4] = { 3, 0x6162, 0x6300, 0 };          /* struct msg: len=3, "abc" */
struct msg *g_msg = (struct msg *)g_msgbuf;
struct packed_rec g_packed = { 0x11, 0x22334455, 0x6677 };
struct reg g_reg = { { 0x12345678 }, 9 };
enum big g_big = BIG_HIGH;
uint64_t g_u64 = 0x8000000000000001ULL;                     /* 8-byte enum in Ghidra */
_Bool g_flag = 1;
char g_neg = (char)0xF0;
const uint16_t g_wide[3] = { 'h', 'i', 0 };                 /* unicode string in Ghidra */
const char g_str[] = "hello?";                              /* string in Ghidra */
uint32_t g_undef4 = 0xCAFEBABE;                             /* undefined4 in Ghidra */
uint32_t g_untyped_word = 0x1234;                           /* label only, no data */
int64_t g_i64 = -5;
filter_fn g_filters[2] = { filter_double, filter_offset };
struct bits16 g_bits = { 21, 99, 9 };
struct sbits g_sbits = { -2, 13 };
struct thing g_thing = { 41, 42 };                          /* "g?thing" / "Thing?Info" */
int g_quote = 7;                                            /* "it's" */
int g_counterA = 100;                                       /* Foo::counter */
int g_counterB = 200;                                       /* Bar::counter */
void *g_opaque = &g_thing;                                  /* struct opaque_s * (placeholder) */
uint32_t g_shifted = 0x100010;                              /* shifted pointer typedef */
int g_dupA[2] = { 1, 2 };                                   /* /A/dup */
int g_dupB = 3;                                             /* /B/dup */
int g_kw = 77;                                              /* named "switch" */
int g_uni = 88;                                             /* named with non-ASCII */
void *g_codeptr = (void *)split_func;                       /* code * */
void *g_fptab[2] = { 0, (void *)split_func };              /* code * via decompiler */
uint32_t g_flag_expect[3];                                  /* GCC's own decode of the flag word */
int g_custom_result[4];
double g_dbl;
volatile int g_edge_result[10];

int Get_Value(int p_arg)
{
    return p_arg * 3 + 1;
}

int ns_init_a(int x)
{
    return x + 1;
}

int ns_init_b(int x)
{
    return x + 2;
}

int sum_va(int n, ...)
{
    va_list ap;
    int total = 0;
    int i;

    va_start(ap, n);
    for (i = 0; i < n; i++)
        total += va_arg(ap, int);
    va_end(ap);
    return total;
}

struct point make_point(int x, int y)
{
    struct point p;
    p.x = x;
    p.y = y;
    return p;
}

double mix(float a, double b, int c)
{
    return a * b + c;
}

int edge_locals(int n)
{
    volatile char buf[16];
    int sum = 0;
    int i;

    for (i = 0; i < n; i++)
        buf[i] = 'a' + i;
    buf[n] = 0;
    for (i = 0; i < n; i++)
        sum += buf[i];
    return sum;
}

int call_ptr(void **tbl)
{
    int (*fp)(void) = (int (*)(void))tbl[1];
    int a = fp();
    return a + fp();
}

uint32_t take_flags(uint32_t raw)
{
    return (raw >> 3) & 0x1f;
}

int sum_pair(int a, int b)
{
    return a * 1000 + b;
}

int stack_pair(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j)
{
    return a + b + c + d + e + f + g + h + i * 1000 + j;
}

uint32_t make_flags(int v)
{
    return ((uint32_t)v << 8) | 5;
}

void edge_done(void)
{
    __asm__ volatile("" ::: "memory");
}

void edge_main(void)
{
    struct point p;

    g_union.f = 1.5f;
    g_edge_result[0] = Get_Value(5);
    g_edge_result[1] = ns_init_a(10);
    g_edge_result[2] = ns_init_b(10);
    g_edge_result[3] = sum_va(3, 10, 20, 30);
    p = make_point(3, -4);
    g_edge_result[4] = p.x * 100 + p.y;
    g_dbl = mix(1.5f, 2.25, 3);
    g_edge_result[5] = edge_locals(7);
    g_edge_result[6] = split_func();
    g_edge_result[7] = asm_between();
    g_edge_result[8] = call_ptr(g_fptab);
    {
        union { uint32_t raw; struct flagword f; } u;
        u.raw = 0x12345678;
        g_flag_expect[0] = u.f.lo;
        g_flag_expect[1] = u.f.mid;
        g_flag_expect[2] = u.f.hi;
        g_custom_result[0] = take_flags(u.raw);
    }
    g_custom_result[1] = sum_pair(12, 34);
    g_custom_result[2] = stack_pair(1, 2, 3, 4, 5, 6, 7, 8, 56, 78);
    g_custom_result[3] = make_flags(0x4321);
    edge_done();
}
