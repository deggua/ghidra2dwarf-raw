/*
 * Code shapes from the adversarial review; see shapes.h.
 */
#include "fw.h"
#include "shapes.h"

volatile int g_shape_sink;
volatile int g_poke;
int g_shape_arr[10];
volatile int g_shape_result[8];

int shape_leaf(int v)
{
    g_shape_sink += v;
    return v + 1;
}

void shape_touch(int *p)
{
    p[0] += 1;
}

void shape_swap(int *x, int *y)
{
    int t = *x;
    *x = *y;
    *y = t;
}

/* "if (n <= 1) return;" before the frame setup: PPC "cmplwi r4,1; blelr",
   ARM "cmp r1,#1; bxls lr" -- a conditional return that falls through. */
void shape_qsort(int *a, unsigned int n)
{
    unsigned int i, last = 0;

    if (n <= 1)
        return;
    shape_swap(&a[0], &a[n / 2]);
    for (i = 1; i < n; i++)
        if (a[i] < a[0])
            shape_swap(&a[++last], &a[i]);
    shape_swap(&a[0], &a[last]);
    shape_qsort(a, last);
    shape_qsort(a + last + 1, n - last - 1);
}

/* conditional epilogue/return on ARM ("pople {r4,r5,r6,pc}") */
int shape_fib(int n)
{
    if (n < 2)
        return n;
    return shape_fib(n - 1) + shape_fib(n - 2);
}

/* conditional move (ARM "moveq", x86 "cmove") into a callee-saved register */
int shape_csel(int a, int b)
{
    int r = 1000;

    if (a == 0)
        r = b;
    shape_leaf(r);
    return r + a;
}

/* frame over 32 KB: PPC "lis r0,-1; ori r0,r0,..; stwux r1,r1,r0" */
int shape_big(int n)
{
    volatile char buf[40000];

    buf[n] = (char)n;
    buf[n + 30000] = (char)shape_leaf(n);
    return buf[n] + buf[n + 30000];
}

/* parameters copied into a stack object whose address escapes: the stack
   copies change behind the analysis' back */
void shape_mutate(struct shape_msg *m)
{
    m->id += 1000;
    m->val = -m->val;
}

int shape_alias(int id, int val)
{
    struct shape_msg m;

    m.id = id;
    m.val = val;
    shape_mutate(&m);
    shape_leaf(m.id + m.val);
    return m.id + id;
}

/* a store as the first instruction (hardware register accessors):
   "break shape_poke" must stop before it */
void shape_poke(volatile int *p, int v)
{
    *p = v;
}

/* over-aligned local: stack realignment */
int shape_align(int n)
{
    int buf[8] __attribute__((aligned(64)));
    int i;

    for (i = 0; i < 8; i++)
        buf[i] = i * n;
    shape_touch(buf);
    return shape_leaf(buf[n]) + 1;      /* (no tail call) */
}

/* "b shape_leaf" at -O1/-O2: a thunk in Ghidra */
int shape_wrap(int v)
{
    return shape_leaf(v);
}

/* ---- second review ------------------------------------------------------- */

/* An early "return -1" whose stub branches back to the shared epilogue at
   -O2: a decompiler basic block of two distant pieces. */
char g_shape_heap[64];
unsigned int g_shape_heap_used;
const char g_shape_path[] = "/a/b";

char *shape_lookup(const char *name)
{
    g_shape_sink += name[0];
    return (char *)g_shape_path;
}

char *shape_alloc(unsigned int n)
{
    char *p = g_shape_heap + g_shape_heap_used;
    if (g_shape_heap_used + n > sizeof g_shape_heap)
        return 0;
    g_shape_heap_used += n;
    return p;
}

char *shape_copy_to(char *dst, const char *src)
{
    while (*src)
        *dst++ = *src++;
    *dst = 0;
    return dst;
}

void shape_fill(char *dst, const char *src, unsigned int n)
{
    while (n--)
        *dst++ = *src++;
}

int shape_finish(const char *name, char *dest)
{
    g_shape_sink += name[0] + (dest ? dest[0] : 0);
    return g_shape_sink & 0xff;
}

void shape_release(char *p)
{
    if (p)
        g_shape_sink ^= p[0];
}

int shape_build(const char *name)
{
    char *dest = 0;
    char *p = shape_lookup(name);
    int r;

    if (__builtin_expect(p != 0 && *p != 0, 0)) {
        dest = shape_alloc(16);
        if (dest == 0)
            return -1;
        p = shape_copy_to(dest, p);
        *p = ':';
        shape_fill(p + 1, "xyz", 3);
    }
    r = shape_finish(name, dest);
    shape_release(dest);
    return r;
}

/* indirect calls (MIPS jalr with delay slots) */
int shape_helper3(int x)
{
    g_shape_sink += x;
    return x * 3;
}

int shape_cb(int x)
{
    g_shape_sink ^= x;
    return x + 1;
}

int shape_two(shape_int_fn fp, int n, int flag)
{
    if (flag)
        return shape_helper3(flag) + 1;
    return fp(n) + fp(n + 1) + n;
}

void shape_cb2(void)
{
    g_shape_sink++;
}

int shape_loop3(shape_void_fn fp, int n)
{
    int i;

    for (i = 0; i != n; i++)
        fp();
    return i;
}

/* Computed goto through a table in RAM that neither Ghidra nor the
   decompiler can resolve (the test setup gives the function its whole
   range as body, as an analyst would), with an indirect tail call among the
   cases, and more cases than the analysis' old round limit. */
int (*g_shape_fp)(int) = shape_helper3;
volatile int g_shape_done;

int shape_dhelper(int x)
{
    g_shape_sink += x;
    return x * 5;
}

#define SD_L(k) &&d##k,
#define SD_C(k) d##k: r = shape_dhelper(r + k); goto out;
#define SD_X10(m, a) m(a##0) m(a##1) m(a##2) m(a##3) m(a##4) m(a##5) m(a##6) m(a##7) m(a##8) m(a##9)
int shape_disp(int op, int x)
{
    static void *tbl[] = { &&tail, SD_X10(SD_L, 1) SD_X10(SD_L, 2) SD_X10(SD_L, 3) SD_X10(SD_L, 4)
                           SD_X10(SD_L, 5) SD_X10(SD_L, 6) SD_X10(SD_L, 7) };
    int r = x * 2 + 1;

    g_shape_sink = r;
    if (g_shape_done == 12345)
        tbl[1] = &&d11;             /* keeps the table writable (RAM) */
    goto *tbl[op];
tail:
    return g_shape_fp(r + 2);
    SD_X10(SD_C, 1) SD_X10(SD_C, 2) SD_X10(SD_C, 3) SD_X10(SD_C, 4)
    SD_X10(SD_C, 5) SD_X10(SD_C, 6) SD_X10(SD_C, 7)
out:
    return r + x;
}

/* prototypes the exporter writes itself (skip_decompile, thunks) with
   pointer parameters */
int shape_take(const char *s, int *p)
{
    return s[0] + *p;
}

int shape_skipme(char *s, int *p, unsigned char b[4])
{
    return s[1] + *p + b[0];
}

int shape_wrap2(const char *s, int *p)
{
    return shape_take(s, p);
}

/* ---- third review ----------------------------------------------------- */

/* call results in a register pair / FPR, kept across the next call */
uint64_t shape_get64(int a)
{
    return ((uint64_t)a << 32) | (unsigned int)(a + 1);
}

float shape_getf(int a)
{
    return (float)a * 1.5f;
}

uint64_t shape_keepll(int a)
{
    uint64_t x = shape_get64(a);
    uint64_t y = shape_get64(a + 1);
    shape_leaf(a + 2);
    return x ^ y;
}

float shape_keepf(int a)
{
    float x = shape_getf(a);
    float y = shape_getf(a + 1);
    shape_leaf(a + 2);
    return x + y;
}

/* an early return inside a loop: return code the decompiler duplicates */
int shape_phi3(int *p, int n)
{
    int s = 0, i;

    for (i = 0; i < n; i++) {
        if (p[i] < 0)
            return -1;
        s += shape_leaf(p[i]);
    }
    if (s > 100)
        s = s - 100;
    else
        s = s + n;
    return s;
}

/* a jump table; cases whose first statement isn't a call */
int shape_switch(int op, int x)
{
    switch (op) {
    case 0: return shape_leaf(x);
    case 1: x = x * x; break;
    case 2: x = x - 5; break;
    case 3: x = x << 2; break;
    case 4: x = x | 1; break;
    case 5: x = -x; break;
    case 6: x = x >> 1; break;
    default: return -1;
    }
    shape_leaf(x);
    return x;
}

/* a jump into a loop body (irreducible): the decompiler prints a goto and
   a label */
int shape_goto(int n)
{
    int s = 0;

    if (n & 1)
        goto mid;
    while (n > 0) {
        s += n;
mid:
        s ^= shape_leaf(n);
        n -= 2;
    }
    return s;
}

void shapes_main(void)
{
    int i;

    for (i = 0; i < 10; i++)
        g_shape_arr[i] = (i * 7) % 10;
    shape_qsort(g_shape_arr, 10);
    g_shape_result[0] = shape_fib(7);
    g_shape_result[1] = shape_csel(0, 77);
    g_shape_result[2] = shape_big(5);
    g_shape_result[3] = shape_alias(42, 7);
    g_poke = 0x1111;
    shape_poke(&g_poke, 0xabcd);
    g_shape_result[4] = shape_align(3);
    g_shape_result[5] = shape_wrap(20);
    g_shape_result[6] = shape_build("n");
    g_shape_sink = shape_two(shape_cb, 5, 0);
    g_shape_sink = shape_two(shape_cb, 1234, 7);
    g_shape_sink = shape_loop3(shape_cb2, 5);
    g_shape_sink = shape_disp(0, 5);
    g_shape_sink = shape_disp(4, 6);
    g_shape_sink = shape_disp(68, 7);
    {
        int v = 7;
        unsigned char b[4] = { 1, 2, 3, 4 };
        g_shape_sink = shape_wrap2("ab", &v) + shape_skipme("cd", &v, b);
    }
    g_shape_sink = (int)shape_keepll(4);
    g_shape_sink = (int)shape_keepf(2);
    g_shape_sink = shape_phi3(g_shape_arr, 3);
    for (i = 0; i < 8; i++)
        g_shape_sink = shape_switch(i, i + 10);
    g_shape_sink = shape_goto(5);
}
