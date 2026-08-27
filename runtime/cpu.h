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
#include "mem_layout.h"

#define ELFISH_MAX_FREE 8192u   /* freed blocks / selectors tracked at once */

/* ── Function-entry trace (opt-in: compile with -DELFISH_TRACE_FN) ── */
/* Gated on g_trace_on so a calibrated busy-delay loop (millions of iterations,
 * no side effects) does not bury the trace. The runtime turns it on at the
 * point of interest -- see ELFISH_TRACE_FROM in tsxlib_stubs.c. */
#ifdef ELFISH_TRACE_FN
extern int g_trace_on;
extern const char *g_cur_fn;    /* last function entered, for the watchpoint */
#define TRACE_FN(n) do { g_cur_fn = (n); if (g_trace_on) fprintf(stderr, "FN %s "  \
    "ax=%04X bx=%04X cx=%04X dx=%04X si=%04X di=%04X bp=%04X sp=%04X "  \
    "ds=%04X es=%04X ss=%04X\n", (n), cpu->ax, cpu->bx, cpu->cx, cpu->dx,  \
    cpu->si, cpu->di, cpu->bp, cpu->sp, cpu->ds, cpu->es, cpu->ss); } while (0)
#else
#define TRACE_FN(n) ((void)0)
#endif

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

    /* Index and pointer registers (32-bit unions for 0x66 operand-size ops). */
    union { uint16_t si; uint32_t esi; };
    union { uint16_t di; uint32_t edi; };
    union { uint16_t bp; uint32_t ebp; };
    union { uint16_t sp; uint32_t esp; };

    /* Segment registers */
    uint16_t cs;
    uint16_t ds;
    uint16_t es;
    uint16_t ss;
    /* 386 extra segment registers (0x64/0x65 prefixes). */
    uint16_t fs;
    uint16_t gs;

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

    /* Selector -> flat base table (65536 entries). Segments 1..NUM_SEG come
     * from the static image layout; dynamically allocated selectors (TSXLIB
     * memory alloc) are filled in at runtime. */
    uint32_t *sel_base;
    uint32_t  heap_next;   /* bump allocator cursor (flat offset) */
    uint32_t  heap_end;    /* end of usable memory */
    uint16_t  next_sel;    /* next dynamic selector to hand out */
    uint32_t *sel_size;    /* bytes bound to each selector (0 = not ours) */
    /* Freed blocks and selectors, for reuse. The guest allocates and frees the
     * same 256KB buffer a thousand times over during startup; a bump allocator
     * that never reclaims runs a 128MB heap dry before the video init. */
    struct { uint32_t base, size; } *free_blk;
    uint32_t  free_cnt;
    uint16_t *free_sel;
    uint32_t  free_sel_cnt;

    /* Emulated BIOS timer tick (0040:006C), advanced on each read so the
     * game's timer wait/calibration loops make progress. */
    uint32_t  bios_ticks;

    /* DOS file handle table (host FILE* per handle; 0..4 reserved). */
    void     *files[256];

    /* Halt flag */
    int halted;
} CPU;

/* ── Memory access ─────────────────────────────────────────── */

/*
 * Protected-mode selector translation. The lifter normalizes every relocated
 * selector to its NE segment index (SEG_n == n); gen_image.py places each
 * segment at SEG_SEGMENT_BASE[n] in the flat image, copied into cpu->sel_base
 * at startup. Dynamically allocated selectors (TSXLIB memory alloc) get fresh
 * entries in sel_base. Unmapped selectors point at an isolated guard region.
 */
static inline uint32_t seg_off(CPU *cpu, uint16_t seg, uint16_t off) {
    return cpu->sel_base[seg] + off;
}

static inline uint8_t mem_read8(CPU *cpu, uint16_t seg, uint16_t off) {
    return cpu->mem[seg_off(cpu, seg, off)];
}

/* Memory watchpoint: ELFISH_WATCH="<seg hex>:<off hex>[+len]" reports every
 * write into that range together with the function doing it. Finding which
 * code fills a buffer is otherwise guesswork, because the pointer is computed
 * rather than a constant the source can be grepped for. */
#ifdef ELFISH_TRACE_FN
extern uint32_t g_watch_seg, g_watch_lo, g_watch_hi;
void watch_write(CPU *cpu, uint16_t seg, uint16_t off, uint32_t val, int size);
#define WATCH(c, s, o, v, n) do { if ((s) == g_watch_seg) watch_write(c, s, o, v, n); } while (0)
#else
#define WATCH(c, s, o, v, n) ((void)0)
#endif

static inline void mem_write8(CPU *cpu, uint16_t seg, uint16_t off, uint8_t val) {
    WATCH(cpu, seg, off, val, 1);
    cpu->mem[seg_off(cpu, seg, off)] = val;
}

static inline uint16_t mem_read16(CPU *cpu, uint16_t seg, uint16_t off) {
    /* Absolute/BIOS-data selector 0xFFFF: emulate the 0040:006C timer tick so
     * the game's timer wait and speed-calibration loops terminate. */
    if (seg == 0xFFFF) {
        if (off == 0x6C) return (uint16_t)(cpu->bios_ticks++);
        if (off == 0x6E) return (uint16_t)(cpu->bios_ticks >> 16);
    }
    uint32_t addr = seg_off(cpu, seg, off);
    return (uint16_t)cpu->mem[addr] | ((uint16_t)cpu->mem[addr + 1] << 8);
}

static inline void mem_write16(CPU *cpu, uint16_t seg, uint16_t off, uint16_t val) {
    WATCH(cpu, seg, off, val, 2);
    uint32_t addr = seg_off(cpu, seg, off);
    cpu->mem[addr] = (uint8_t)(val & 0xFF);
    cpu->mem[addr + 1] = (uint8_t)(val >> 8);
}

static inline uint32_t mem_read32(CPU *cpu, uint16_t seg, uint16_t off) {
    return (uint32_t)mem_read16(cpu, seg, off) |
           ((uint32_t)mem_read16(cpu, seg, off + 2) << 16);
}

static inline void mem_write32(CPU *cpu, uint16_t seg, uint16_t off, uint32_t val) {
    WATCH(cpu, seg, off, val, 4);
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

/* 32-bit stack ops (operand-size 0x66 prefix). SP is still 16-bit. */
static inline void push32(CPU *cpu, uint32_t val) {
    cpu->sp -= 4;
    mem_write32(cpu, cpu->ss, cpu->sp, val);
}

static inline uint32_t pop32(CPU *cpu) {
    uint32_t val = mem_read32(cpu, cpu->ss, cpu->sp);
    cpu->sp += 4;
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

/* ── 32-bit flag helpers (operand-size 0x66 prefix) ────────── */

static inline void set_szp32(CPU *cpu, uint32_t r) {
    cpu->flags &= ~(FLAG_SF | FLAG_ZF | FLAG_PF);
    if (r & 0x80000000u) cpu->flags |= FLAG_SF;
    if (r == 0)          cpu->flags |= FLAG_ZF;
    if (parity8((uint8_t)r)) cpu->flags |= FLAG_PF;
}

static inline uint32_t flags_add32(CPU *cpu, uint32_t a, uint32_t b) {
    uint64_t r = (uint64_t)a + b;
    uint32_t result = (uint32_t)r;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (r > 0xFFFFFFFFu) cpu->flags |= FLAG_CF;
    if (((a ^ result) & (b ^ result)) & 0x80000000u) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp32(cpu, result);
    return result;
}

static inline uint32_t flags_sub32(CPU *cpu, uint32_t a, uint32_t b) {
    uint32_t result = a - b;
    cpu->flags &= ~(FLAG_CF | FLAG_OF | FLAG_AF);
    if (a < b) cpu->flags |= FLAG_CF;
    if (((a ^ b) & (a ^ result)) & 0x80000000u) cpu->flags |= FLAG_OF;
    if (((a ^ b ^ result) & 0x10)) cpu->flags |= FLAG_AF;
    set_szp32(cpu, result);
    return result;
}

static inline void flags_cmp32(CPU *cpu, uint32_t a, uint32_t b) { flags_sub32(cpu, a, b); }

static inline void flags_logic32(CPU *cpu, uint32_t r) {
    cpu->flags &= ~(FLAG_CF | FLAG_OF);
    set_szp32(cpu, r);
}

static inline void flags_shift32(CPU *cpu, uint32_t r) { set_szp32(cpu, r); }

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
    cpu->sel_base = (uint32_t *)malloc(65536u * sizeof(uint32_t));
    cpu->sel_size = (uint32_t *)calloc(65536u, sizeof(uint32_t));
    cpu->free_blk = malloc(ELFISH_MAX_FREE * sizeof(*cpu->free_blk));
    cpu->free_sel = (uint16_t *)malloc(ELFISH_MAX_FREE * sizeof(uint16_t));
    cpu->free_cnt = cpu->free_sel_cnt = 0;
    if (!cpu->mem || !cpu->sel_base || !cpu->sel_size || !cpu->free_blk || !cpu->free_sel) return 0;
    /* Default every selector to the guard region, then map the static image
     * segments (1..NUM_SEG) to their flat bases. */
    for (uint32_t s = 0; s < 65536u; s++)
        cpu->sel_base[s] = ELFISH_GUARD_BASE;
    for (int s = 0; s <= ELFISH_NUM_SEG; s++)
        cpu->sel_base[s] = SEG_SEGMENT_BASE[s];
    /* Dynamic heap lives past the loaded image; selectors start well above the
     * NE range to avoid colliding with raw/hardcoded selectors. */
    cpu->heap_next = (ELFISH_IMAGE_SIZE + 0xFu) & ~0xFu;
    cpu->heap_end = size;
    cpu->next_sel = 0x4000;
    return 1;
}

/* Allocate `bytes` from the flat heap and bind a fresh selector to it.
 * Returns the selector (0 on out-of-memory). The region is already zeroed. */
static inline uint16_t cpu_alloc_selector(CPU *cpu, uint32_t bytes) {
    if (bytes == 0) bytes = 16;
    bytes = (bytes + 0xFu) & ~0xFu;
    uint32_t base = 0;
    /* First fit over reclaimed blocks, then bump. Splitting the remainder back
     * keeps a run of same-sized alloc/free pairs from fragmenting the heap. */
    for (uint32_t i = 0; i < cpu->free_cnt; i++) {
        if (cpu->free_blk[i].size < bytes) continue;
        base = cpu->free_blk[i].base;
        if (cpu->free_blk[i].size >= bytes + 16u) {
            cpu->free_blk[i].base += bytes;
            cpu->free_blk[i].size -= bytes;
        } else {
            bytes = cpu->free_blk[i].size;
            cpu->free_blk[i] = cpu->free_blk[--cpu->free_cnt];
        }
        break;
    }
    if (!base) {
        base = (cpu->heap_next + 0xFu) & ~0xFu;
        if (base + bytes > cpu->heap_end) return 0;
        cpu->heap_next = base + bytes;
    }
    uint16_t sel;
    if (cpu->free_sel_cnt) sel = cpu->free_sel[--cpu->free_sel_cnt];
    else if (cpu->next_sel) sel = cpu->next_sel++;
    else return 0;
    cpu->sel_base[sel] = base;
    cpu->sel_size[sel] = bytes;
    memset(cpu->mem + base, 0, bytes);   /* callers expect a zeroed block */
    return sel;
}

/* Return a dynamically allocated selector's memory to the free list. Ignores
 * anything that is not one of ours, so a caller passing the wrong register is
 * a no-op rather than corruption.
 * ponytail: first-fit with no coalescing, and a full list simply leaks the
 * block. Coalesce if fragmentation ever shows up as an allocation failure. */
static inline void cpu_free_selector(CPU *cpu, uint16_t sel) {
    if (sel < 0x4000u || !cpu->sel_size[sel]) return;
    if (cpu->free_cnt < ELFISH_MAX_FREE) {
        cpu->free_blk[cpu->free_cnt].base = cpu->sel_base[sel];
        cpu->free_blk[cpu->free_cnt].size = cpu->sel_size[sel];
        cpu->free_cnt++;
    }
    if (cpu->free_sel_cnt < ELFISH_MAX_FREE) cpu->free_sel[cpu->free_sel_cnt++] = sel;
    cpu->sel_size[sel] = 0;
    cpu->sel_base[sel] = ELFISH_GUARD_BASE;
}

/* ── Protected-mode selector queries (LAR / LSL) ──────────────
 * A selector is "valid" if it maps to a real (non-guard) segment. LAR returns
 * standard present/writable data-segment access rights; LSL returns a max
 * 16-bit limit (we don't track per-selector sizes yet). Both set the guest ZF
 * via their boolean return (1 = valid). */
static inline int cpu_sel_valid(CPU *cpu, uint16_t sel) {
    return sel != 0 && cpu->sel_base[sel] != ELFISH_GUARD_BASE;
}

static inline int cpu_lar(CPU *cpu, uint16_t sel, uint16_t *out) {
    if (!cpu_sel_valid(cpu, sel)) return 0;
    *out = 0x0093;  /* present, ring 0, data, read/write, accessed */
    return 1;
}

static inline int cpu_lsl(CPU *cpu, uint16_t sel, uint16_t *out) {
    if (!cpu_sel_valid(cpu, sel)) return 0;
    *out = 0xFFFF;
    return 1;
}

static inline void cpu_free(CPU *cpu) {
    free(cpu->mem);
    free(cpu->sel_base);
    free(cpu->sel_size); free(cpu->free_blk); free(cpu->free_sel);
    cpu->sel_size = NULL; cpu->free_blk = NULL; cpu->free_sel = NULL;
    cpu->mem = NULL;
    cpu->sel_base = NULL;
}

/* Port I/O. The VGA register model lives in tsxlib_stubs.c, so these are
 * declarations rather than the stubs they used to be -- once the game is really
 * programming the CRTC, "everything reads back zero" is a wrong answer, not a
 * missing one. */
uint8_t port_in8(CPU *cpu, uint16_t port);
void port_out8(CPU *cpu, uint16_t port, uint8_t val);
/* 16-bit port access. The VGA/VESA and sound registers this game drives are
 * mostly paired 8-bit ports written as one word (index in AL, data in AH), so
 * split it rather than inventing a separate word-wide device model. */
static inline uint16_t port_in16(CPU *cpu, uint16_t port) {
    return (uint16_t)(port_in8(cpu, port) | (port_in8(cpu, (uint16_t)(port + 1)) << 8));
}

static inline void port_out16(CPU *cpu, uint16_t port, uint16_t val) {
    port_out8(cpu, port, (uint8_t)val);
    port_out8(cpu, (uint16_t)(port + 1), (uint8_t)(val >> 8));
}

#endif /* ELFISH_CPU_H */
