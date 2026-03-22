/*
 * cpu.h - CPU State and Runtime for El-Fish Static Recompilation
 *
 * Extends pcrecomp's cpu.h with:
 * - x87 FPU state (8-register stack, control/status words)
 * - NE segment support (segment selectors map to flat memory regions)
 * - TSXLIB runtime stubs
 *
 * El-Fish is a protected-mode NE executable, NOT a real-mode MZ.
 * Memory addressing uses segment selectors that map to flat memory
 * regions rather than real-mode seg<<4+off computation.
 */

#ifndef ELFISH_CPU_H
#define ELFISH_CPU_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

/* ── Flag bits ─────────────────────────────────────────────── */

#define FLAG_CF  0x0001
#define FLAG_PF  0x0004
#define FLAG_AF  0x0010
#define FLAG_ZF  0x0040
#define FLAG_SF  0x0080
#define FLAG_TF  0x0100
#define FLAG_IF  0x0200
#define FLAG_DF  0x0400
#define FLAG_OF  0x0800

/* ── FPU constants ─────────────────────────────────────────── */

#define FPU_STACK_SIZE  8
#define FPU_C0  0x0100
#define FPU_C1  0x0200
#define FPU_C2  0x0400
#define FPU_C3  0x4000

/* ── CPU State ─────────────────────────────────────────────── */

typedef struct CPU {
    /* General-purpose registers */
    union { struct { uint8_t al, ah; }; uint16_t ax; uint32_t eax; };
    union { struct { uint8_t bl, bh; }; uint16_t bx; uint32_t ebx; };
    union { struct { uint8_t cl, ch; }; uint16_t cx; uint32_t ecx; };
    union { struct { uint8_t dl, dh; }; uint16_t dx; uint32_t edx; };

    /* Index and pointer registers */
    uint16_t si;
    uint16_t di;
    uint16_t bp;
    uint16_t sp;

    /* Segment registers */
    uint16_t cs;
    uint16_t ds;
    uint16_t es;
    uint16_t ss;

    /* Instruction pointer (debug) */
    uint16_t ip;

    /* Flags register */
    uint16_t flags;

    /* x87 FPU state */
    double   st[FPU_STACK_SIZE];  /* FPU register stack */
    int      fpu_top;             /* Top-of-stack pointer (0-7) */
    uint16_t fpu_control;         /* FPU control word */
    uint16_t fpu_status;          /* FPU status word */
    uint16_t fpu_tag;             /* FPU tag word */

    /* Flat memory */
    uint8_t *mem;
    uint32_t mem_size;

    /* Halt flag */
    int halted;
} CPU;

/* ── Memory access ─────────────────────────────────────────── */

/*
 * El-Fish uses protected-mode segments via TSXLIB. In the recomp,
 * segment selectors map to flat memory offsets via a segment table.
 * For now, we use real-mode-style seg<<4+off addressing as a
 * placeholder until the segment table is fully reconstructed.
 */

static inline uint32_t seg_off(uint16_t seg, uint16_t off) {
    return ((uint32_t)seg << 4) + off;
}

static inline uint8_t mem_read8(CPU *cpu, uint16_t seg, uint16_t off) {
    return cpu->mem[seg_off(seg, off)];
}

static inline void mem_write8(CPU *cpu, uint16_t seg, uint16_t off, uint8_t val) {
    cpu->mem[seg_off(seg, off)] = val;
}

static inline uint16_t mem_read16(CPU *cpu, uint16_t seg, uint16_t off) {
    uint32_t addr = seg_off(seg, off);
    return (uint16_t)cpu->mem[addr] | ((uint16_t)cpu->mem[addr + 1] << 8);
}

static inline void mem_write16(CPU *cpu, uint16_t seg, uint16_t off, uint16_t val) {
    uint32_t addr = seg_off(seg, off);
    cpu->mem[addr] = (uint8_t)(val & 0xFF);
    cpu->mem[addr + 1] = (uint8_t)(val >> 8);
}

static inline uint32_t mem_read32(CPU *cpu, uint16_t seg, uint16_t off) {
    return (uint32_t)mem_read16(cpu, seg, off) |
           ((uint32_t)mem_read16(cpu, seg, off + 2) << 16);
}

static inline void mem_write32(CPU *cpu, uint16_t seg, uint16_t off, uint32_t val) {
    mem_write16(cpu, seg, off, (uint16_t)(val & 0xFFFF));
    mem_write16(cpu, seg, off + 2, (uint16_t)(val >> 16));
}

/* ── Stack operations ──────────────────────────────────────── */

static inline void push16(CPU *cpu, uint16_t val) {
    cpu->sp -= 2;
    mem_write16(cpu, cpu->ss, cpu->sp, val);
}

static inline uint16_t pop16(CPU *cpu) {
    uint16_t val = mem_read16(cpu, cpu->ss, cpu->sp);
    cpu->sp += 2;
    return val;
}

/* ── Flag helpers ──────────────────────────────────────────── */

static inline int parity8(uint8_t v) {
    v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
    return (~v) & 1;
}

static inline void set_szp8(CPU *cpu, uint8_t r) {
    cpu->flags &= ~(FLAG_SF | FLAG_ZF | FLAG_PF);
    if (r & 0x80) cpu->flags |= FLAG_SF;
    if (r == 0)   cpu->flags |= FLAG_ZF;
    if (parity8(r)) cpu->flags |= FLAG_PF;
}

static inline void set_szp16(CPU *cpu, uint16_t r) {
    cpu->flags &= ~(FLAG_SF | FLAG_ZF | FLAG_PF);
    if (r & 0x8000) cpu->flags |= FLAG_SF;
    if (r == 0)     cpu->flags |= FLAG_ZF;
    if (parity8((uint8_t)r)) cpu->flags |= FLAG_PF;
}

static inline uint8_t flags_add8(CPU *cpu, uint8_t a, uint8_t b) {
    uint16_t r = (uint16_t)a + b;
    uint8_t result = (uint8_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (r > 0xFF) cpu->flags |= FLAG_CF;
    if (((a ^ result) & (b ^ result)) & 0x80) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp8(cpu, result);
    return result;
}

static inline uint16_t flags_add16(CPU *cpu, uint16_t a, uint16_t b) {
    uint32_t r = (uint32_t)a + b;
    uint16_t result = (uint16_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (r > 0xFFFF) cpu->flags |= FLAG_CF;
    if (((a ^ result) & (b ^ result)) & 0x8000) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp16(cpu, result);
    return result;
}

static inline uint8_t flags_sub8(CPU *cpu, uint8_t a, uint8_t b) {
    uint16_t r = (uint16_t)a - b;
    uint8_t result = (uint8_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (a < b) cpu->flags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & 0x80) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp8(cpu, result);
    return result;
}

static inline uint16_t flags_sub16(CPU *cpu, uint16_t a, uint16_t b) {
    uint32_t r = (uint32_t)a - b;
    uint16_t result = (uint16_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (a < b) cpu->flags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & 0x8000) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp16(cpu, result);
    return result;
}

static inline void flags_cmp8(CPU *cpu, uint8_t a, uint8_t b)  { flags_sub8(cpu, a, b); }
static inline void flags_cmp16(CPU *cpu, uint16_t a, uint16_t b) { flags_sub16(cpu, a, b); }

static inline void flags_logic8(CPU *cpu, uint8_t r) {
    cpu->flags &= ~(FLAG_CF | FLAG_OF);
    set_szp8(cpu, r);
}

static inline void flags_logic16(CPU *cpu, uint16_t r) {
    cpu->flags &= ~(FLAG_CF | FLAG_OF);
    set_szp16(cpu, r);
}

static inline void flags_shift8(CPU *cpu, uint8_t r)  { set_szp8(cpu, r); }
static inline void flags_shift16(CPU *cpu, uint16_t r) { set_szp16(cpu, r); }

/* ── Flag test helpers ─────────────────────────────────────── */

static inline int cf(CPU *cpu) { return (cpu->flags & FLAG_CF) != 0; }
static inline int zf(CPU *cpu) { return (cpu->flags & FLAG_ZF) != 0; }
static inline int sf(CPU *cpu) { return (cpu->flags & FLAG_SF) != 0; }
static inline int of(CPU *cpu) { return (cpu->flags & FLAG_OF) != 0; }
static inline int pf(CPU *cpu) { return (cpu->flags & FLAG_PF) != 0; }
static inline int af(CPU *cpu) { return (cpu->flags & FLAG_AF) != 0; }
static inline int df(CPU *cpu) { return (cpu->flags & FLAG_DF) != 0; }

/* ── Condition code tests ──────────────────────────────────── */

static inline int cc_o(CPU *cpu)  { return of(cpu); }
static inline int cc_no(CPU *cpu) { return !of(cpu); }
static inline int cc_b(CPU *cpu)  { return cf(cpu); }
static inline int cc_ae(CPU *cpu) { return !cf(cpu); }
static inline int cc_e(CPU *cpu)  { return zf(cpu); }
static inline int cc_ne(CPU *cpu) { return !zf(cpu); }
static inline int cc_be(CPU *cpu) { return cf(cpu) || zf(cpu); }
static inline int cc_a(CPU *cpu)  { return !cf(cpu) && !zf(cpu); }
static inline int cc_s(CPU *cpu)  { return sf(cpu); }
static inline int cc_ns(CPU *cpu) { return !sf(cpu); }
static inline int cc_p(CPU *cpu)  { return pf(cpu); }
static inline int cc_np(CPU *cpu) { return !pf(cpu); }
static inline int cc_l(CPU *cpu)  { return sf(cpu) != of(cpu); }
static inline int cc_ge(CPU *cpu) { return sf(cpu) == of(cpu); }
static inline int cc_le(CPU *cpu) { return zf(cpu) || (sf(cpu) != of(cpu)); }
static inline int cc_g(CPU *cpu)  { return !zf(cpu) && (sf(cpu) == of(cpu)); }

/* ── FPU operations ────────────────────────────────────────── */

static inline void fpu_init(CPU *cpu) {
    memset(cpu->st, 0, sizeof(cpu->st));
    cpu->fpu_top = 0;
    cpu->fpu_control = 0x037F;  /* Default: all exceptions masked, round to nearest */
    cpu->fpu_status = 0;
    cpu->fpu_tag = 0xFFFF;      /* All registers empty */
}

static inline void fpu_push(CPU *cpu) {
    cpu->fpu_top = (cpu->fpu_top - 1) & 7;
    /* Shift logical stack: st[7] is lost, everything moves up */
    for (int i = 7; i > 0; i--)
        cpu->st[i] = cpu->st[i - 1];
    cpu->st[0] = 0.0;
}

static inline void fpu_pop(CPU *cpu) {
    for (int i = 0; i < 7; i++)
        cpu->st[i] = cpu->st[i + 1];
    cpu->st[7] = 0.0;
    cpu->fpu_top = (cpu->fpu_top + 1) & 7;
}

static inline void fpu_compare(CPU *cpu, double a, double b) {
    cpu->fpu_status &= ~(FPU_C0 | FPU_C2 | FPU_C3);
    if (a != a || b != b) {
        /* NaN: unordered */
        cpu->fpu_status |= FPU_C0 | FPU_C2 | FPU_C3;
    } else if (a > b) {
        /* Nothing set */
    } else if (a < b) {
        cpu->fpu_status |= FPU_C0;
    } else {
        /* Equal */
        cpu->fpu_status |= FPU_C3;
    }
    /* Mirror to CPU flags for FSTSW AX / SAHF pattern */
    cpu->ah = (uint8_t)(cpu->fpu_status >> 8);
}

/* FPU memory read/write helpers (placeholder - uses seg:off addressing) */
static inline double fpu_read_f32(CPU *cpu, uint16_t seg, uint16_t off) {
    uint32_t bits = mem_read32(cpu, seg, off);
    float f;
    memcpy(&f, &bits, sizeof(f));
    return (double)f;
}

static inline double fpu_read_f64(CPU *cpu, uint16_t seg, uint16_t off) {
    uint32_t lo = mem_read32(cpu, seg, off);
    uint32_t hi = mem_read32(cpu, seg, off + 4);
    uint64_t bits = (uint64_t)lo | ((uint64_t)hi << 32);
    double d;
    memcpy(&d, &bits, sizeof(d));
    return d;
}

static inline void fpu_write_f32(CPU *cpu, uint16_t seg, uint16_t off, double val) {
    float f = (float)val;
    uint32_t bits;
    memcpy(&bits, &f, sizeof(bits));
    mem_write32(cpu, seg, off, bits);
}

static inline void fpu_write_f64(CPU *cpu, uint16_t seg, uint16_t off, double val) {
    uint64_t bits;
    memcpy(&bits, &val, sizeof(bits));
    mem_write32(cpu, seg, off, (uint32_t)(bits & 0xFFFFFFFF));
    mem_write32(cpu, seg, off + 4, (uint32_t)(bits >> 32));
}

static inline int32_t fpu_read_i16(CPU *cpu, uint16_t seg, uint16_t off) {
    return (int32_t)(int16_t)mem_read16(cpu, seg, off);
}

static inline int32_t fpu_read_i32(CPU *cpu, uint16_t seg, uint16_t off) {
    return (int32_t)mem_read32(cpu, seg, off);
}

static inline void fpu_write_i16(CPU *cpu, uint16_t seg, uint16_t off, int32_t val) {
    mem_write16(cpu, seg, off, (uint16_t)(int16_t)val);
}

static inline void fpu_write_i32(CPU *cpu, uint16_t seg, uint16_t off, int32_t val) {
    mem_write32(cpu, seg, off, (uint32_t)val);
}

/* ── CPU lifecycle ─────────────────────────────────────────── */

static inline void cpu_init(CPU *cpu) {
    memset(cpu, 0, sizeof(*cpu));
    cpu->flags = 0x0002;
    fpu_init(cpu);
}

static inline int cpu_alloc_mem(CPU *cpu, uint32_t size) {
    cpu->mem = (uint8_t *)calloc(1, size);
    cpu->mem_size = size;
    return cpu->mem != NULL;
}

static inline void cpu_free(CPU *cpu) {
    free(cpu->mem);
    cpu->mem = NULL;
}

/* ── Port I/O stubs ────────────────────────────────────────── */

static inline uint8_t port_in8(CPU *cpu, uint16_t port) {
    (void)cpu; (void)port;
    return 0;
}

static inline void port_out8(CPU *cpu, uint16_t port, uint8_t val) {
    (void)cpu; (void)port; (void)val;
}

#endif /* ELFISH_CPU_H */
