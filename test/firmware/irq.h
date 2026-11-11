/* Interrupt test prototypes (parsed by Ghidra's C parser too). */

extern volatile int g_ticks;
extern volatile int g_syscalls;
extern volatile int g_traps;
extern volatile uint32_t g_trap_pc;
extern volatile int g_irq_result[4];

int syscall_handler(int num, int arg);
void program_check(uint32_t pc);
void timer_tick(void);
int busy_work(int n);
void irq_test(void);

int do_syscall(int num, int arg);
void trap_now(void);
void irq_enable(uint32_t dec);
void irq_disable(void);
