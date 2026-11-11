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
}
