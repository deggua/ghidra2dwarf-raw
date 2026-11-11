/*
 * Interrupt test (targets with exception vectors in the test firmware).
 * The C side of the handlers in <isa>/irq.S plus a driver called from
 * _cstart before edge_main(). Checked by test/gdb_irq_checks.py.
 */
#include "fw.h"
#include "irq.h"

volatile int g_ticks;
volatile int g_syscalls;
volatile int g_traps;
volatile uint32_t g_trap_pc;
volatile int g_irq_result[8];
volatile uint32_t g_saved_r30;
volatile int g_probe;

int syscall_handler(int num, int arg)
{
    g_syscalls++;
    return num + arg;
}

void program_check(uint32_t pc)
{
    g_traps++;
    g_trap_pc = pc;
}

void timer_tick(void)
{
    g_ticks++;
}

int busy_work(int n)
{
    int acc = 0;
    int i;

    for (i = 0; i < n; i++) {
        acc += i * 3;
        if (g_ticks >= 3)
            break;
    }
    return acc;
}

int shape_probe(int v)
{
    g_probe += v;
    return v * 2;
}

/* q lives in a callee-saved register here; shape_os saves it with
   _savegpr_29 before reusing the register */
int shape_os_caller(int p, int q)
{
    int r = shape_os(p, q, 3);
    return r + q;
}

void irq_test(void)
{
    g_irq_result[0] = do_syscall(7, 35);
    trap_now();
    g_irq_result[1] = g_traps;
    irq_enable(20000);
    while (g_ticks < 3)
        g_irq_result[2] = busy_work(100000000);
    irq_disable();
    g_irq_result[3] = 0x1234;
    g_irq_result[4] = shape_os_caller(111, 222);
    g_irq_result[5] = early_init(5);
}
