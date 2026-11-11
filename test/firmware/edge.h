/*
 * Edge-case types and prototypes (parsed by Ghidra's C parser after fw.h).
 * test/ghidra_setup_edge.py then applies the "only possible in Ghidra"
 * annotations on top: names with '?', namespaces, 8-byte enums, shifted
 * pointers, placeholder structs, duplicate type names, ...
 */

#pragma pack(push, 1)
struct packed_rec {
    uint8_t tag;
    uint32_t value;
    uint16_t crc;
};
#pragma pack(pop)

struct bits16 {
    uint16_t a : 5;
    uint16_t b : 7;
    uint16_t c : 4;
};

struct sbits {
    int s : 3;
    int u : 5;
};

struct msg {
    uint16_t len;
    uint8_t data[];
};

struct reg {
    union {
        uint32_t word;
        struct {
            uint16_t hi;
            uint16_t lo;
        } half;
    };
    uint32_t ctrl;
};

enum big {
    BIG_LOW = 0,
    BIG_MID = 0x7fffffff,
    BIG_HIGH = 0xF0000000,
    BIG_ALIAS = 0xF0000000
};

struct thing {
    int field_q;
    int ok;
};

int Get_Value(int p_arg);
int ns_init_a(int x);
int ns_init_b(int x);
int sum_va(int n, ...);
struct point make_point(int x, int y);
double mix(float a, double b, int c);
int edge_locals(int n);
int split_func(void);
int asm_between(void);
int call_ptr(void **tbl);
void edge_done(void);
void edge_main(void);
