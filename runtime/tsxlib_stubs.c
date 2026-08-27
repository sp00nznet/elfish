/*
 * tsxlib_stubs.c - Host runtime stub implementations for El-Fish Recomp.
 *
 * NO-OP / minimal placeholders for the software interrupts and TSXLIB ordinal
 * trampolines referenced by the lifted code. These let the program link and
 * start; real behavior (DOS/BIOS services, protected-mode memory, file I/O)
 * is implemented incrementally.
 */
#include "runtime_api.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <conio.h>
#include <windows.h>

/* Flip to 1 to trace every runtime call while bringing the program up. */
#ifndef ELFISH_TRACE_RUNTIME
#define ELFISH_TRACE_RUNTIME 0
#endif

#ifndef ELFISH_GAME_DIR
#define ELFISH_GAME_DIR "game/ELFISH"
#endif

/* ---- DOS file I/O backed by the host game directory ---- */

static const char *game_dir(void) {
    const char *d = getenv("ELFISH_GAME_DIR");
    return d ? d : ELFISH_GAME_DIR;
}

/* Read an ASCIIZ string from guest memory at seg:off. */
static void read_asciiz(CPU *cpu, uint16_t seg, uint16_t off, char *out, int max) {
    int i = 0;
    for (; i < max - 1; i++) {
        uint8_t c = mem_read8(cpu, seg, (uint16_t)(off + i));
        if (c == 0) break;
        out[i] = (char)c;
    }
    out[i] = 0;
}

/* Map a DOS path to a host path under the game dir: drop drive, '\\'->'/'. */
static void map_path(const char *dos, char *out, int max) {
    const char *p = dos;
    if (p[0] && p[1] == ':') p += 2;        /* strip drive letter */
    while (*p == '\\' || *p == '/') p++;    /* strip leading slashes */
    snprintf(out, max, "%s/%s", game_dir(), p);
    for (char *q = out; *q; q++) if (*q == '\\') *q = '/';
}

/* Open a guest file case-insensitively (DOS is case-insensitive; host may not).
 * Tries the mapped path, then all-lower and all-upper of the final component. */
static FILE *host_open(const char *dos, const char *mode) {
    char path[512];
    map_path(dos, path, sizeof(path));
    FILE *f = fopen(path, mode);
    if (f) return f;
    char *slash = strrchr(path, '/');
    char *name = slash ? slash + 1 : path;
    char save[256];
    snprintf(save, sizeof(save), "%s", name);
    for (char *q = name; *q; q++) *q = (char)tolower((unsigned char)*q);
    if ((f = fopen(path, mode))) return f;
    snprintf(name, sizeof(save), "%s", save);
    for (char *q = name; *q; q++) *q = (char)toupper((unsigned char)*q);
    return fopen(path, mode);
}

/* Allocate a DOS handle (>=5) for a host FILE*. Returns 0xFFFF if full. */
static uint16_t dos_handle_alloc(CPU *cpu, FILE *f) {
    for (int h = 5; h < 256; h++) {
        if (!cpu->files[h]) { cpu->files[h] = f; return (uint16_t)h; }
    }
    return 0xFFFF;
}

#if ELFISH_TRACE_RUNTIME
#define TRACE(...) fprintf(stderr, __VA_ARGS__)
#else
#define TRACE(...) ((void)0)
#endif

/* Function tracing (-DELFISH_TRACE_FN) starts off and arms on an INT21 call
 * named by ELFISH_TRACE_FROM as "<AH hex>" or "<AH hex>:<Nth occurrence>".
 * Without a trigger the trace is buried under the tens of millions of
 * iterations of the calibrated delay loop that runs before anything
 * interesting. Unset = never; "00" = from the start. */
int g_trace_on = 0;

static void trace_arm(uint8_t ah) {
    static int seen = 0;
    const char *from = getenv("ELFISH_TRACE_FROM");
    if (g_trace_on || !from) return;
    char *end;
    if (ah != (uint8_t)strtol(from, &end, 16)) return;
    long nth = (*end == ':') ? strtol(end + 1, NULL, 10) : 1;
    if (++seen >= nth) g_trace_on = 1;
}

/* A zero divisor would be undefined behaviour in C; report it and carry on. */
void catz_div0(const char *op) {
    fprintf(stderr, "DIVIDE BY ZERO in %s\n", op);
}

/* ---- Software interrupts ---- */
void dos_int21(CPU *cpu)
{
    TRACE("INT21 ah=%02X al=%02X ds:dx=%04X:%04X\n", cpu->ah, cpu->al, cpu->ds, cpu->dx);
    trace_arm(cpu->ah);
    switch (cpu->ah) {
    case 0x4C:  /* terminate process with return code in AL */
        printf("[INT21/4C] program requested exit, code=%u\n", cpu->al);
        fflush(stdout);
        exit(cpu->al);
    case 0x30:  /* get DOS version -> report 5.00 */
        cpu->al = 5; cpu->ah = 0; cpu->bx = 0; cpu->cx = 0;
        break;
    case 0x51:  /* get PSP selector */
    case 0x62:
        cpu->bx = (uint16_t)cpu_alloc_selector(cpu, 0x100);  /* zeroed fake PSP */
        break;
    case 0x25:  /* set interrupt vector - ignore */
        break;
    case 0x35:  /* get interrupt vector -> null */
        cpu->es = 0; cpu->bx = 0;
        break;
    case 0x19:  /* current default drive -> C: */
        cpu->al = 2;
        break;

    case 0x3D: {  /* open existing file: DS:DX=name, AL=mode -> AX=handle */
        char name[256]; read_asciiz(cpu, cpu->ds, cpu->dx, name, sizeof(name));
        const char *mode = ((cpu->al & 3) == 1) ? "r+b" : ((cpu->al & 3) == 2) ? "r+b" : "rb";
        FILE *f = host_open(name, mode);
        TRACE("INT21 open '%s' -> %s\n", name, f ? "ok" : "FAIL");
        if (!f) { cpu->flags |= FLAG_CF; cpu->ax = 2; }
        else { cpu->ax = dos_handle_alloc(cpu, f); cpu->flags &= ~FLAG_CF; }
        break;
    }
    case 0x3C: {  /* create/truncate file: DS:DX=name -> AX=handle */
        char name[256]; read_asciiz(cpu, cpu->ds, cpu->dx, name, sizeof(name));
        FILE *f = host_open(name, "w+b");
        TRACE("INT21 create '%s' -> %s\n", name, f ? "ok" : "FAIL");
        if (!f) { cpu->flags |= FLAG_CF; cpu->ax = 3; }
        else { cpu->ax = dos_handle_alloc(cpu, f); cpu->flags &= ~FLAG_CF; }
        break;
    }
    case 0x3E:  /* close handle in BX */
        if (cpu->bx >= 5 && cpu->bx < 256 && cpu->files[cpu->bx]) {
            fclose((FILE *)cpu->files[cpu->bx]);
            cpu->files[cpu->bx] = NULL;
        }
        cpu->flags &= ~FLAG_CF;
        break;
    case 0x3F: {  /* read: BX=handle, CX=count, DS:DX=buf -> AX=bytes read */
        uint16_t h = cpu->bx, n = cpu->cx, got = 0;
        if (h >= 5 && h < 256 && cpu->files[h]) {
            for (; got < n; got++) {
                int c = fgetc((FILE *)cpu->files[h]);
                if (c == EOF) break;
                mem_write8(cpu, cpu->ds, (uint16_t)(cpu->dx + got), (uint8_t)c);
            }
        }
        cpu->ax = got; cpu->flags &= ~FLAG_CF;
        break;
    }
    case 0x40: {  /* write: BX=handle, CX=count, DS:DX=buf -> AX=bytes written */
        uint16_t h = cpu->bx, n = cpu->cx, i;
        FILE *out = (h == 1) ? stdout : (h == 2) ? stderr
                  : (h >= 5 && h < 256) ? (FILE *)cpu->files[h] : NULL;
        for (i = 0; out && i < n; i++)
            fputc(mem_read8(cpu, cpu->ds, (uint16_t)(cpu->dx + i)), out);
        cpu->ax = n; cpu->flags &= ~FLAG_CF;
        break;
    }
    case 0x42: {  /* lseek: BX=handle, CX:DX=offset, AL=whence -> DX:AX=pos */
        uint16_t h = cpu->bx;
        if (h >= 5 && h < 256 && cpu->files[h]) {
            long off = (long)(((uint32_t)cpu->cx << 16) | cpu->dx);
            int whence = (cpu->al == 1) ? SEEK_CUR : (cpu->al == 2) ? SEEK_END : SEEK_SET;
            fseek((FILE *)cpu->files[h], off, whence);
            long pos = ftell((FILE *)cpu->files[h]);
            cpu->ax = (uint16_t)(pos & 0xFFFF); cpu->dx = (uint16_t)((pos >> 16) & 0xFFFF);
            cpu->flags &= ~FLAG_CF;
        } else { cpu->flags |= FLAG_CF; cpu->ax = 6; }
        break;
    }
    case 0x2C: {  /* get time -> CH=hour CL=min DH=sec DL=centisec (advancing) */
        static uint32_t t = 0; t += 3;
        cpu->ch = (uint8_t)((t / 360000u) % 24u);
        cpu->cl = (uint8_t)((t / 6000u) % 60u);
        cpu->dh = (uint8_t)((t / 100u) % 60u);
        cpu->dl = (uint8_t)(t % 100u);
        break;
    }
    case 0x2A:  /* get date -> CX=year DH=month DL=day AL=weekday */
        cpu->cx = 1993; cpu->dh = 1; cpu->dl = 1; cpu->al = 5;
        break;
    case 0x47:  /* get current directory: DL=drive, DS:SI=64-byte buffer */
        mem_write8(cpu, cpu->ds, cpu->si, 0);  /* report root of game dir */
        cpu->ax = 0x0100; cpu->flags &= ~FLAG_CF;
        break;
    case 0x3B: {  /* chdir: DS:DX=path. Host paths always resolve against the
                   * game dir, so there is no cwd to move -- just succeed. */
        char name[256]; read_asciiz(cpu, cpu->ds, cpu->dx, name, sizeof(name));
        TRACE("INT21 chdir '%s'\n", name);
        cpu->flags &= ~FLAG_CF;
        break;
    }
    case 0x41: {  /* delete file: DS:DX=name */
        char name[256], path[512];
        read_asciiz(cpu, cpu->ds, cpu->dx, name, sizeof(name));
        map_path(name, path, sizeof(path));
        int ok = (remove(path) == 0);
        TRACE("INT21 unlink '%s' -> %s\n", name, ok ? "ok" : "FAIL");
        if (ok) cpu->flags &= ~FLAG_CF;
        else { cpu->flags |= FLAG_CF; cpu->ax = 2; }
        break;
    }
    case 0x43: {  /* get/set file attributes: DS:DX=name, AL=0 get -> CX=attr */
        char name[256]; read_asciiz(cpu, cpu->ds, cpu->dx, name, sizeof(name));
        FILE *f = host_open(name, "rb");
        TRACE("INT21 attr-%s '%s' -> %s\n", cpu->al ? "set" : "get", name,
              f ? "exists" : "MISSING");
        if (f) fclose(f);
        if (!f) { cpu->flags |= FLAG_CF; cpu->ax = 2; }   /* file not found */
        else { cpu->cx = 0x20; cpu->flags &= ~FLAG_CF; }  /* archive bit */
        break;
    }
    case 0x44:  /* IOCTL: AL=0 get device info for handle in BX */
        if (cpu->al == 0) {
            /* handles 0/1/2 are character devices (bit 7 set); files clear it */
            cpu->dx = (cpu->bx <= 2) ? 0x80 : 0x00;
            cpu->flags &= ~FLAG_CF;
        }
        break;

    default:
        /* DOS reports an unsupported call as CF=1, AX=1. Leaving the flags
         * untouched is not "do nothing": the caller tests CF, so an
         * unimplemented service takes a random branch depending on whatever
         * set the flags last. Fail loudly and deterministically instead. */
        fprintf(stderr, "INT21 ah=%02X al=%02X UNHANDLED\n", cpu->ah, cpu->al);
        cpu->flags |= FLAG_CF;
        cpu->ax = 1;
        break;
    }
}
/* ---- Video BIOS (INT 10h) ----
 * Text-mode queries only, so the C runtime can place its console output. The
 * graphics modes go to SDL later; until then a mode set is accepted and
 * ignored rather than reported as failed. */
void bios_int10(CPU *cpu)
{
    TRACE("INT10 ah=%02X al=%02X\n", cpu->ah, cpu->al);
    switch (cpu->ah) {
    case 0x03:  /* get cursor position and size: BH=page */
        cpu->cx = 0x0607;   /* a normal underline cursor for an 8-line cell */
        cpu->dx = 0;        /* DH=row, DL=column -- top left */
        break;
    case 0x0F:  /* get video mode -> AL=mode, AH=columns, BH=page */
        cpu->al = 0x03;     /* 80x25 colour text */
        cpu->ah = 80;
        cpu->bh = 0;
        break;
    case 0x12:  /* get EGA/VGA configuration */
        if (cpu->bl == 0x10) { cpu->bh = 0; cpu->bl = 3; cpu->cx = 0x0009; }
        break;
    case 0x1A:  /* get display combination code -> VGA + colour monitor */
        cpu->al = 0x1A; cpu->bx = 0x0008;
        break;
    default:
        break;      /* mode sets, cursor moves, scrolls: accepted, no display yet */
    }
}
/* ---- Keyboard (INT 16h) ----
 * Backed by the host console via conio, so the DOS-era text prompts are
 * really interactive. When stdin is not a console _kbhit() just reports no
 * key, which is the correct "nobody pressed anything" answer rather than a
 * fabricated one. Extended keys arrive from _getch() as a 0/0xE0 lead byte
 * followed by the scan code; INT 16h wants those as AL=0, AH=scan.
 * ponytail: console only. SDL takes over once there is a video window. */
static int kb_pending = -1;   /* one-key pushback for the peek/read pair */

static int kb_poll(void) {
    if (kb_pending >= 0) return kb_pending;
    if (!_kbhit()) return -1;
    int c = _getch();
    if (c == 0 || c == 0xE0) kb_pending = (_getch() & 0xFF) << 8;  /* AL=0, AH=scan */
    else kb_pending = (c & 0xFF) | ((c & 0xFF) << 8);              /* ascii in AL */
    return kb_pending;
}

void bios_int16(CPU *cpu)
{
    TRACE("INT16 ah=%02X\n", cpu->ah);
    switch (cpu->ah) {
    case 0x00: case 0x10: {  /* wait for a key, remove it from the buffer */
        int k;
        while ((k = kb_poll()) < 0)
            Sleep(5);        /* a real BIOS spins here; do not burn a core */
        kb_pending = -1;
        cpu->ax = (uint16_t)k;
        cpu->flags &= ~FLAG_ZF;
        break;
    }
    case 0x01: case 0x11: {  /* peek: ZF=1 when the buffer is empty */
        int k = kb_poll();
        if (k < 0) { cpu->flags |= FLAG_ZF; }
        else { cpu->ax = (uint16_t)k; cpu->flags &= ~FLAG_ZF; }
        break;
    }
    case 0x02: case 0x12:    /* shift/toggle state: nothing held */
        cpu->al = 0;
        break;
    default:
        break;
    }
}
void mouse_int33(CPU *cpu) { TRACE("INT33 ax=%04X\n", cpu->ax); (void)cpu; }
void int_handler(CPU *cpu, int int_num) { TRACE("INT %02X\n", int_num); (void)cpu; (void)int_num; }

/* ---- TSXLIB ordinals ----
 * These are reached through the far-call convention the lifter emits
 * (push cs; push 0; <ordinal>(cpu)), so each must clean up the 4-byte far
 * return address exactly as the real routine's RETF would (cpu->sp += 4).
 * Omitting this leaks stack and corrupts the caller's saved registers. */
#define TSX_STUB(name) void name(CPU *cpu) { TRACE("%s\n", #name); cpu->sp += 4; }
TSX_STUB(tsx_fpu_dispatch)
TSX_STUB(tsx_fpu_wait)
TSX_STUB(tsx_fpu_memop)
TSX_STUB(tsx_init_3)
TSX_STUB(tsx_init_4)
TSX_STUB(tsx_init_14)
TSX_STUB(tsx_seg_load)
TSX_STUB(tsx_seg_unload)
TSX_STUB(tsx_seg_call)
TSX_STUB(tsx_seg_jmp)
TSX_STUB(tsx_seg_ref)
TSX_STUB(tsx_seg_fixup_call)
TSX_STUB(tsx_seg_fixup_jmp)
/* TSXLIB ordinal 32 is the extender's software-interrupt gateway -- int86x(),
 * not a DOS-only call despite the name. The interrupt number is pushed as a
 * word argument and the routine returns with RETF 2, consuming it; the C
 * runtime's intdos()/int86x() (seg209_12E5) relies on that to get its own BP
 * back off the stack, so the 2 extra bytes are load-bearing, not bookkeeping.
 * The register set is already loaded from the caller's REGS struct on entry
 * and is copied back out afterwards. */
void tsx_dos_call(CPU *cpu) {
    uint16_t intno = mem_read16(cpu, cpu->ss, (uint16_t)(cpu->sp + 4));
    TRACE("tsx_dos_call int %02X ax=%04X\n", intno, cpu->ax);
    switch (intno) {
    case 0x21: dos_int21(cpu);   break;
    case 0x10: bios_int10(cpu);  break;
    case 0x16: bios_int16(cpu);  break;
    case 0x33: mouse_int33(cpu); break;
    default:   int_handler(cpu, intno); break;
    }
    cpu->sp += 6;   /* RETF 2 */
}
TSX_STUB(tsx_file_getinfo)
TSX_STUB(tsx_file_read)
TSX_STUB(tsx_file_close)
TSX_STUB(tsx_int_io)
TSX_STUB(tsx_set_handler)
TSX_STUB(tsx_save_context)
/* tsx_mem_alloc / _small: allocate a block sized by AX (paragraphs); return the
 * selector in AX (0 = failure). At least a full 64K segment is backed so any
 * in-segment offset is valid. */
static void tsx_mem_alloc_impl(CPU *cpu) {
    uint32_t bytes = (uint32_t)cpu->ax * 16u;
    if (bytes < 0x10000u) bytes = 0x10000u;
    uint16_t sel = cpu_alloc_selector(cpu, bytes);
    cpu->ax = sel;
    if (sel) cpu->flags &= ~FLAG_CF; else cpu->flags |= FLAG_CF;
    cpu->sp += 4;
}
void tsx_mem_alloc(CPU *cpu)       { TRACE("tsx_mem_alloc\n");       tsx_mem_alloc_impl(cpu); }
void tsx_mem_alloc_small(CPU *cpu) { TRACE("tsx_mem_alloc_small\n"); tsx_mem_alloc_impl(cpu); }
TSX_STUB(tsx_mem_free)
TSX_STUB(tsx_file_open)  /* needs faithful stream-object RE; see memory notes */
TSX_STUB(tsx_mem_realloc)
TSX_STUB(tsx_mem_lock)
TSX_STUB(tsx_desc_alloc)
TSX_STUB(tsx_desc_get_base)
/* tsx_huge_alloc: allocate a large block; return far pointer dx:ax (selector
 * in dx, offset 0 in ax), CF clear on success. Caller: `mov si,ax; mov ds,dx`
 * then walks/initializes a zeroed free-list inside the block. */
void tsx_huge_alloc(CPU *cpu) {
    TRACE("tsx_huge_alloc\n");
    uint16_t sel = cpu_alloc_selector(cpu, 0x100000u);  /* 1 MB */
    cpu->ax = 0;
    cpu->dx = sel;
    if (sel) cpu->flags &= ~FLAG_CF; else cpu->flags |= FLAG_CF;
    cpu->sp += 4;
}
TSX_STUB(tsx_huge_free)
TSX_STUB(tsx_file_create)
TSX_STUB(tsx_file_write)
TSX_STUB(tsx_file_seek)
