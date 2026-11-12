/* Interrupt test prototypes (parsed by Ghidra's C parser too). */

extern volatile int g_ticks;
extern volatile int g_syscalls;
extern volatile int g_traps;
extern volatile uint32_t g_trap_pc;
extern volatile int g_irq_result[8];
extern volatile uint32_t g_saved_r30;
extern volatile int g_probe;

int syscall_handler(int num, int arg);
void program_check(uint32_t pc);
void timer_tick(void);
int busy_work(int n);
void irq_test(void);

int do_syscall(int num, int arg);
void trap_now(void);
void irq_enable(uint32_t dec);
void irq_disable(void);
void irq_fatal(int code);
void msr_keep(void);

int shape_probe(int v);
int shape_os(int a, int b, int c);
int shape_os_caller(int p, int q);
int early_init(int v);
