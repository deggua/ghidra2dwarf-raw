/*
 * Code shapes found by the adversarial review (parsed by Ghidra's C parser
 * too). Each function compiles into a pattern that once broke the flow
 * analysis; test/difftrace.py single-steps through them comparing the
 * unwinding with GCC's own CFI, and test/gdb_edge_checks.py checks values.
 */

struct shape_msg {
    int id;
    int val;
};

extern volatile int g_shape_sink;
extern volatile int g_poke;
extern int g_shape_arr[10];
extern volatile int g_shape_result[8];

int shape_leaf(int v);
void shape_touch(int *p);
void shape_swap(int *x, int *y);
void shape_qsort(int *a, unsigned int n);
int shape_fib(int n);
int shape_csel(int a, int b);
int shape_big(int n);
void shape_mutate(struct shape_msg *m);
int shape_alias(int id, int val);
void shape_poke(volatile int *p, int v);
int shape_align(int n);
int shape_wrap(int v);
void shapes_main(void);
