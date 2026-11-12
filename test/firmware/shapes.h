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
extern char g_shape_heap[64];
extern unsigned int g_shape_heap_used;

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
char *shape_lookup(const char *name);
char *shape_alloc(unsigned int n);
char *shape_copy_to(char *dst, const char *src);
void shape_fill(char *dst, const char *src, unsigned int n);
int shape_finish(const char *name, char *dest);
void shape_release(char *p);
int shape_build(const char *name);
int shape_helper3(int x);
int shape_cb(int x);
/* (named types: Ghidra's C parser names an anonymous function-pointer type
   after its parameter, so "int (*fp)(int)" and "void (*fp)(void)" would be
   one type "fp") */
typedef int (*shape_int_fn)(int);
typedef void (*shape_void_fn)(void);
int shape_two(shape_int_fn fp, int n, int flag);
void shape_cb2(void);
int shape_loop3(shape_void_fn fp, int n);
int shape_dhelper(int x);
int shape_disp(int op, int x);
int shape_take(const char *s, int *p);
int shape_skipme(char *s, int *p, unsigned char b[4]);
int shape_wrap2(const char *s, int *p);
uint64_t shape_get64(int a);
float shape_getf(int a);
uint64_t shape_keepll(int a);
float shape_keepf(int a);
int shape_phi3(int *p, int n);
int shape_switch(int op, int x);
void shapes_main(void);
