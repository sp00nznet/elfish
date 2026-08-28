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
#include <sys/stat.h>
#include <dirent.h>
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

/* Resolve a guest path onto the host, case-insensitively (DOS does not care;
 * the host might). Tries the mapped path, then all-lower and all-upper of the
 * final component. Returns 1 if something is there, with `out` left holding the
 * spelling that worked and `attr` the DOS attribute byte. */
static int host_resolve(const char *dos, char *out, int max, unsigned *attr) {
    char save[256];
    map_path(dos, out, max);
    char *slash = strrchr(out, '/');
    char *name = slash ? slash + 1 : out;
    snprintf(save, sizeof(save), "%s", name);
    for (int pass = 0; pass < 3; pass++) {
        if (pass == 1)
            for (char *q = name; *q; q++) *q = (char)tolower((unsigned char)*q);
        else if (pass == 2)
            for (char *q = name; *q; q++) *q = (char)toupper((unsigned char)*q);
        struct stat st;
        if (stat(out, &st) == 0) {
            /* A directory has to be reported as one. The game validates the data
             * directories named in ELFISH.RED by asking for their attributes, and
             * fopen cannot answer for a directory -- reporting \FISH missing put
             * an "Incorrect RED/Subdir" box on the title screen. */
            if (attr) *attr = (st.st_mode & S_IFDIR) ? 0x10u : 0x20u;
            return 1;
        }
        snprintf(name, sizeof(save), "%s", save);
    }
    return 0;
}

/* Open a guest file, resolving its name the same way. */
static FILE *host_open(const char *dos, const char *mode) {
    char path[512];
    if (host_resolve(dos, path, sizeof(path), NULL))
        return fopen(path, mode);
    /* Not there yet -- a create still has to work. */
    map_path(dos, path, sizeof(path));
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
static uint16_t g_vesa_bank = 0;   /* VBE window position, in granularity units */
static uint16_t g_vesa_start_x = 0, g_vesa_start_y = 0;   /* VBE display start */

int g_trace_on = 0;
#ifdef ELFISH_TRACE_FN
const char *g_cur_fn = "?";
/* No segment is 0xFFFFFFFF, so an unset watch never matches. */
uint32_t g_watch_seg = 0xFFFFFFFFu, g_watch_lo = 0, g_watch_hi = 0;

void watch_write(CPU *cpu, uint16_t seg, uint16_t off, uint32_t val, int size) {
    if (off + (uint32_t)size <= g_watch_lo || off >= g_watch_hi) return;
    fprintf(stderr, "WATCH %04X:%04X <- %0*X (%d) in %-16s ds:si=%04X:%04X es:di=%04X:%04X cx=%04X ax=%04X bx=%04X\n",
            seg, off, size * 2, val, size, g_cur_fn,
            cpu->ds, cpu->si, cpu->es, cpu->di, cpu->cx, cpu->ax, cpu->bx);
}

/* ELFISH_WATCH="<seg hex>:<off hex>[+len]" -- see cpu.h. */
static void watch_init(void) {
    const char *w = getenv("ELFISH_WATCH");
    if (!w) return;
    char *end;
    unsigned long s = strtoul(w, &end, 16);
    if (*end != ':') return;
    unsigned long o = strtoul(end + 1, &end, 16);
    unsigned long n = (*end == '+') ? strtoul(end + 1, NULL, 16) : 1;
    g_watch_seg = (uint32_t)s; g_watch_lo = (uint32_t)o; g_watch_hi = (uint32_t)(o + n);
    fprintf(stderr, "watching %04lX:%04lX+%lX\n", s, o, n);
}
#else
static void watch_init(void) { }
#endif

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

/* ---- Directory search (INT21 AH=1A/4E/4F) ----
 * DOS returns search results by writing a 43-byte block into the caller's DTA
 * and keeps its own state in the first 21 bytes of it, so a find-next knows
 * where the previous find got to. We do the same, storing a slot index there,
 * which is what lets two searches be open at once without one clobbering the
 * other. The game enumerates its fish and tank libraries this way.
 * ponytail: 8 concurrent searches, and a directory read in one go at find-first
 * so a file appearing mid-scan cannot confuse it. */
#define DTA_MAGIC 0x454C  /* "EL" -- marks a block as one of ours */
#define MAX_FIND  8

static struct {
    int   used;
    char  pattern[16];   /* the 8.3 mask, uppercased */
    char  dir[512];      /* host directory being walked */
    char  names[512][16];
    int   count, pos;
} g_find[MAX_FIND];

static uint16_t g_dta_seg, g_dta_off;   /* INT21 AH=1A */

/* Match a DOS 8.3 mask. `*` runs to the end of its field, `?` is one character;
 * name and mask are both "NAME.EXT" with the dot present only if there is one. */
static int dos_match(const char *mask, const char *name) {
    for (;;) {
        if (*mask == '*') {
            /* Skip to this field's end in both, then keep comparing. */
            while (*mask && *mask != '.') mask++;
            while (*name && *name != '.') name++;
            continue;
        }
        if (!*mask && !*name) return 1;
        if (!*mask || !*name) return 0;
        if (*mask != '?' && *mask != *name) return 0;
        mask++; name++;
    }
}

/* Split a mapped host path into its directory and the mask on the end. */
static void split_mask(const char *path, char *dir, int dmax, char *mask, int mmax) {
    const char *slash = strrchr(path, '/');
    if (slash) {
        int n = (int)(slash - path);
        if (n >= dmax) n = dmax - 1;
        memcpy(dir, path, n); dir[n] = 0;
        snprintf(mask, mmax, "%s", slash + 1);
    } else {
        snprintf(dir, dmax, ".");
        snprintf(mask, mmax, "%s", path);
    }
    for (char *q = mask; *q; q++) *q = (char)toupper((unsigned char)*q);
}

/* Write one result into the DTA and report success. */
static void find_emit(CPU *cpu, int slot) {
    const char *nm = g_find[slot].names[g_find[slot].pos++];
    char full[600];
    snprintf(full, sizeof(full), "%s/%s", g_find[slot].dir, nm);
    struct stat st;
    unsigned long size = (stat(full, &st) == 0) ? (unsigned long)st.st_size : 0;
    unsigned attr = (stat(full, &st) == 0 && (st.st_mode & S_IFDIR)) ? 0x10u : 0x20u;

    uint16_t s = g_dta_seg, o = g_dta_off;
    mem_write16(cpu, s, o, DTA_MAGIC);
    mem_write16(cpu, s, (uint16_t)(o + 2), (uint16_t)slot);
    mem_write8(cpu, s, (uint16_t)(o + 0x15), (uint8_t)attr);
    mem_write16(cpu, s, (uint16_t)(o + 0x16), 0);          /* time */
    mem_write16(cpu, s, (uint16_t)(o + 0x18), 0x2101);     /* date: 1993-08-01 */
    mem_write16(cpu, s, (uint16_t)(o + 0x1A), (uint16_t)(size & 0xFFFF));
    mem_write16(cpu, s, (uint16_t)(o + 0x1C), (uint16_t)(size >> 16));
    for (int i = 0; i < 13; i++)
        mem_write8(cpu, s, (uint16_t)(o + 0x1E + i), (uint8_t)(i < 12 ? nm[i] : 0));
    cpu->flags &= ~FLAG_CF;
    cpu->ax = 0;
}

static void find_fail(CPU *cpu) {
    cpu->flags |= FLAG_CF;
    cpu->ax = 18;   /* no more files */
}

/* ---- Software interrupts ---- */
void dos_int21(CPU *cpu)
{
    TRACE("INT21 ah=%02X al=%02X ds:dx=%04X:%04X\n", cpu->ah, cpu->al, cpu->ds, cpu->dx);
    static int once = 0;
    if (!once) { once = 1; watch_init(); }
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
        char name[256], path[512]; unsigned attr = 0;
        read_asciiz(cpu, cpu->ds, cpu->dx, name, sizeof(name));
        int ok = host_resolve(name, path, sizeof(path), &attr);
        TRACE("INT21 attr-%s '%s' -> %s\n", cpu->al ? "set" : "get", name,
              ok ? (attr == 0x10u ? "dir" : "file") : "MISSING");
        if (!ok) { cpu->flags |= FLAG_CF; cpu->ax = 2; }   /* file not found */
        else { cpu->cx = (uint16_t)attr; cpu->flags &= ~FLAG_CF; }
        break;
    }
    case 0x1A:  /* set DTA: DS:DX is where search results get written */
        g_dta_seg = cpu->ds; g_dta_off = cpu->dx;
        break;

    case 0x4E: {  /* find first: DS:DX=mask, CX=attributes */
        char name[256], path[512], dir[512], mask[16];
        read_asciiz(cpu, cpu->ds, cpu->dx, name, sizeof(name));
        map_path(name, path, sizeof(path));
        split_mask(path, dir, sizeof(dir), mask, sizeof(mask));
        int slot = -1;
        for (int k = 0; k < MAX_FIND; k++) if (!g_find[k].used) { slot = k; break; }
        if (slot < 0) slot = 0;    /* all busy: reuse the oldest rather than fail */
        DIR *d = opendir(dir);
        TRACE("INT21 findfirst '%s' -> dir=%s mask=%s %s\n", name, dir, mask,
              d ? "ok" : "NO DIR");
        if (!d) { find_fail(cpu); break; }
        g_find[slot].used = 1; g_find[slot].count = g_find[slot].pos = 0;
        snprintf(g_find[slot].dir, sizeof(g_find[slot].dir), "%s", dir);
        snprintf(g_find[slot].pattern, sizeof(g_find[slot].pattern), "%s", mask);
        struct dirent *e;
        while ((e = readdir(d)) && g_find[slot].count < 512) {
            if (e->d_name[0] == '.') continue;   /* . .. and dotfiles */
            char up[16];
            snprintf(up, sizeof(up), "%s", e->d_name);
            for (char *q = up; *q; q++) *q = (char)toupper((unsigned char)*q);
            if (dos_match(mask, up))
                snprintf(g_find[slot].names[g_find[slot].count++], 16, "%s", up);
        }
        closedir(d);
        if (!g_find[slot].count) { g_find[slot].used = 0; find_fail(cpu); break; }
        find_emit(cpu, slot);
        break;
    }

    case 0x4F: {  /* find next: state lives in the DTA the last call wrote */
        if (mem_read16(cpu, g_dta_seg, g_dta_off) != DTA_MAGIC) { find_fail(cpu); break; }
        int slot = (int)mem_read16(cpu, g_dta_seg, (uint16_t)(g_dta_off + 2));
        if (slot < 0 || slot >= MAX_FIND || !g_find[slot].used) { find_fail(cpu); break; }
        if (g_find[slot].pos >= g_find[slot].count) {
            g_find[slot].used = 0;   /* exhausted; the slot is free again */
            find_fail(cpu);
            break;
        }
        find_emit(cpu, slot);
        break;
    }

    case 0x36:  /* get free disk space: DL=drive -> AX=sectors/cluster,
                 * BX=free clusters, CX=bytes/sector, DX=total clusters.
                 * An ordinary roomy FAT volume; the game only wants to know
                 * whether there is room to write a tank. */
        cpu->ax = 8;
        cpu->cx = 512;
        cpu->dx = 0xFFFF;
        cpu->bx = 0xFFF0;
        break;
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
/* ---- VGA registers ----
 * Index/data pairs with a register file behind them: a write to the index port
 * selects, the data port then reads or writes that register, and a read gives
 * back what was written. That last part is the whole point. The driver reads
 * CRTC 0x13 (the scanline offset the BIOS programmed for the mode) and builds a
 * pointer out of it; answering 0, as the old stub did, made that pointer null
 * and the C runtime reported a null-pointer fatal instead.
 *
 * ponytail: a register file, not a CRTC -- writes are remembered, not obeyed.
 * Nothing here changes what is displayed, because nothing displays yet. */
static uint8_t g_crtc[0x40], g_seq[0x10], g_gfx[0x10], g_atc[0x20];
static uint8_t g_crtc_i, g_seq_i, g_gfx_i, g_atc_i, g_atc_flip;
static uint8_t g_dac[768], g_dac_mask = 0xFF;
static uint16_t g_dac_w, g_dac_r;
static uint8_t g_misc = 0x67;   /* colour, both page bits, 25MHz -- a VGA default */

/* CRTC 0x13 is the offset register: the BIOS leaves it at bytes-per-line / 8 in
 * a 256-colour mode, and the driver reads it back rather than assuming. */
static void vga_set_pitch(unsigned bytes_per_line) {
    g_crtc[0x13] = (uint8_t)(bytes_per_line / 8u);
}

static int g_vga_init = 0;

void port_out8(CPU *cpu, uint16_t port, uint8_t val) {
    (void)cpu;
    switch (port) {
    case 0x3C0:   /* attribute controller: one port, index then data */
        if (!g_atc_flip) g_atc_i = val & 0x1F; else g_atc[g_atc_i] = val;
        g_atc_flip ^= 1;
        break;
    case 0x3C2: g_misc = val; break;
    case 0x3C4: g_seq_i  = val & 0x0F; break;
    case 0x3C5: g_seq[g_seq_i] = val; break;
    case 0x3C6: g_dac_mask = val; break;
    case 0x3C7: g_dac_r = (uint16_t)(val * 3u); break;
    case 0x3C8: g_dac_w = (uint16_t)(val * 3u); break;
    case 0x3C9: g_dac[g_dac_w % 768u] = val; g_dac_w = (uint16_t)((g_dac_w + 1) % 768u); break;
    case 0x3CE: g_gfx_i  = val & 0x0F; break;
    case 0x3CF: g_gfx[g_gfx_i] = val; break;
    case 0x3B4: case 0x3D4: g_crtc_i = val & 0x3F; break;
    case 0x3B5: case 0x3D5: g_crtc[g_crtc_i] = val; break;
    default: break;   /* other devices: accepted and dropped */
    }
}

uint8_t port_in8(CPU *cpu, uint16_t port) {
    (void)cpu;
    /* 80-column text until a mode set says otherwise. */
    if (!g_vga_init) { g_vga_init = 1; vga_set_pitch(640); }
    switch (port) {
    case 0x3C0: return g_atc_i;
    case 0x3C1: return g_atc[g_atc_i];
    case 0x3C2: return 0x10;   /* input status 0: switch sense */
    case 0x3C4: return g_seq_i;
    case 0x3C5: return g_seq[g_seq_i];
    case 0x3C6: return g_dac_mask;
    case 0x3C9: { uint8_t v = g_dac[g_dac_r % 768u]; g_dac_r = (uint16_t)((g_dac_r + 1) % 768u); return v; }
    case 0x3CC: return g_misc;
    case 0x3CE: return g_gfx_i;
    case 0x3CF: return g_gfx[g_gfx_i];
    case 0x3B4: case 0x3D4: return g_crtc_i;
    case 0x3B5: case 0x3D5: return g_crtc[g_crtc_i];
    case 0x3BA: case 0x3DA: {
        /* Input status 1. Reading it also resets the attribute flip-flop. Bit 0
         * is display-enable and bit 3 vertical retrace; toggle both, because a
         * retrace wait spins until it sees the edge it is waiting for and a
         * constant answer hangs whichever way it is wired. */
        static uint8_t t;
        g_atc_flip = 0;
        t++;
        return (uint8_t)(((t & 1) ? 0x01 : 0) | ((t & 2) ? 0x08 : 0));
    }
    default: return 0xFF;   /* an absent device floats high, not low */
    }
}

/* The one mode we advertise: VBE 0x100, 640x400x256 in a banked window. */
#define VESA_MODE      0x0100u
#define VESA_WIDTH     640u
#define VESA_HEIGHT    400u
#define VESA_VRAM_64K  16u        /* 1 MB, in 64KB units */

/* ---- Video memory ----
 * The driver takes its framebuffer selector from seg29:[0x13], which the DOS
 * extender is supposed to fill with a selector mapping the VESA window. Ours
 * never did, so the slot kept the 0xFFFF it is initialised to -- and 0xFFFF is
 * also the BIOS-data selector the timer tick is read through, so every pixel
 * the game drew landed on top of it. Publishing a real selector is the
 * extender's job, and here we are the extender.
 *
 * VBE 1.2 has no linear framebuffer: the guest sees one 64KB window and moves
 * it with 4F05. Keep the whole of video memory behind it and swap the window
 * on each bank change, so what the guest draws accumulates into one image.
 * ponytail: copy in and out on every bank switch. Point the selector straight
 * into the backing store if that ever shows up in a profile. */
#define VRAM_BYTES (VESA_VRAM_64K * 0x10000u)

static uint8_t *g_vram;
static uint16_t g_fb_sel;
static unsigned g_fb_bank;

void elfish_video_init(CPU *cpu) {
    g_vram = (uint8_t *)calloc(1, VRAM_BYTES);
    g_fb_sel = cpu_alloc_selector(cpu, 0x10000u);
    g_fb_bank = 0;
    /* seg29:[0x13] is the video selector; [0x11] is a separate one. */
    mem_write16(cpu, 29, 0x13, g_fb_sel);
}

/* Move the 64KB window to `bank`, carrying the guest's pixels with it. */
static void vesa_set_bank(CPU *cpu, unsigned bank) {
    if (!g_vram || !g_fb_sel) return;
    uint8_t *win = cpu->mem + cpu->sel_base[g_fb_sel];
    if (g_fb_bank < VESA_VRAM_64K)
        memcpy(g_vram + g_fb_bank * 0x10000u, win, 0x10000u);
    g_fb_bank = bank;
    if (bank < VESA_VRAM_64K)
        memcpy(win, g_vram + bank * 0x10000u, 0x10000u);
}

/* Write what the game has drawn so far as a PPM, colours through the DAC. */
void elfish_dump_framebuffer(CPU *cpu, const char *path) {
    if (!g_vram) return;
    vesa_set_bank(cpu, g_fb_bank);      /* flush the live window first */
    FILE *f = fopen(path, "wb");
    if (!f) return;
    /* If nothing has set the palette yet, show the raw indices as grey rather
     * than a black rectangle -- an unset palette should not look like an unset
     * framebuffer. */
    int dac_empty = 1;
    for (unsigned i = 0; i < 768 && dac_empty; i++) if (g_dac[i]) dac_empty = 0;
    fprintf(f, "P6\n%u %u\n255\n", VESA_WIDTH, VESA_HEIGHT);
    for (unsigned i = 0; i < VESA_WIDTH * VESA_HEIGHT; i++) {
        uint8_t c = g_vram[i];
        if (dac_empty) { fputc(c, f); fputc(c, f); fputc(c, f); continue; }
        /* The DAC holds 6-bit components, as VGA always has. */
        fputc((int)(g_dac[c * 3 + 0] << 2), f);
        fputc((int)(g_dac[c * 3 + 1] << 2), f);
        fputc((int)(g_dac[c * 3 + 2] << 2), f);
    }
    fclose(f);
    { unsigned nz = 0, dz = 0;
      for (unsigned i = 0; i < VRAM_BYTES; i++) if (g_vram[i]) nz++;
      for (unsigned i = 0; i < 768; i++) if (g_dac[i]) dz++;
      fprintf(stderr, "wrote %s (%ux%u) nonzero pixels=%u, DAC entries set=%u, sel=%04X\n",
              path, VESA_WIDTH, VESA_HEIGHT, nz, dz, g_fb_sel); }
}

/* ---- VESA / VBE 1.2 (INT 10h AX=4Fxx) ----
 * The game asks for mode 0x100, 640x400x256, through a banked 64KB window at
 * A000 -- the SVGA path its box advertises. Reporting one mode honestly is
 * better than reporting a long list we cannot set. Everything here describes a
 * plain VBE 1.2 banked framebuffer; there is no linear-framebuffer capability
 * bit, because there is no VBE 2.0.
 * ponytail: the window is real memory and nothing displays it yet. Wiring it to
 * SDL is the next step; the shape of what the guest writes does not change. */
static void vesa_str(CPU *cpu, uint16_t seg, uint16_t off, const char *s) {
    for (; *s; s++, off++) mem_write8(cpu, seg, off, (uint8_t)*s);
    mem_write8(cpu, seg, off, 0);
}

static void vesa(CPU *cpu) {
    uint16_t seg = cpu->es, off = cpu->di;
    switch (cpu->al) {
    case 0x00: {   /* get controller info -> 512-byte VbeInfoBlock at ES:DI */
        for (uint16_t i = 0; i < 512; i++) mem_write8(cpu, seg, (uint16_t)(off + i), 0);
        vesa_str(cpu, seg, off, "VESA");
        mem_write16(cpu, seg, (uint16_t)(off + 0x04), 0x0102);   /* VBE 1.2 */
        /* OEM string and the mode list live in the tail of the same block, so
         * the far pointers stay inside memory the caller already owns. */
        mem_write16(cpu, seg, (uint16_t)(off + 0x06), (uint16_t)(off + 0x100));
        mem_write16(cpu, seg, (uint16_t)(off + 0x08), seg);
        mem_write16(cpu, seg, (uint16_t)(off + 0x0A), 0);        /* no capabilities */
        mem_write16(cpu, seg, (uint16_t)(off + 0x0C), 0);
        mem_write16(cpu, seg, (uint16_t)(off + 0x0E), (uint16_t)(off + 0x140));
        mem_write16(cpu, seg, (uint16_t)(off + 0x10), seg);
        mem_write16(cpu, seg, (uint16_t)(off + 0x12), VESA_VRAM_64K);
        vesa_str(cpu, seg, (uint16_t)(off + 0x100), "El-Fish Recomp");
        mem_write16(cpu, seg, (uint16_t)(off + 0x140), VESA_MODE);
        mem_write16(cpu, seg, (uint16_t)(off + 0x142), 0xFFFF);  /* end of list */
        cpu->ax = 0x004F;
        break;
    }
    case 0x01: {   /* get mode info for CX -> 256-byte ModeInfoBlock at ES:DI */
        if ((cpu->cx & 0x7FFF) != VESA_MODE) { cpu->ax = 0x014F; break; }
        for (uint16_t i = 0; i < 256; i++) mem_write8(cpu, seg, (uint16_t)(off + i), 0);
        /* supported | colour | graphics | BIOS-supported output */
        mem_write16(cpu, seg, (uint16_t)(off + 0x00), 0x001B);
        mem_write8(cpu, seg, (uint16_t)(off + 0x02), 0x07);      /* window A: exists/read/write */
        mem_write8(cpu, seg, (uint16_t)(off + 0x03), 0x00);      /* window B: none */
        mem_write16(cpu, seg, (uint16_t)(off + 0x04), 64);       /* granularity, KB */
        mem_write16(cpu, seg, (uint16_t)(off + 0x06), 64);       /* window size, KB */
        mem_write16(cpu, seg, (uint16_t)(off + 0x08), 0xA000);
        mem_write16(cpu, seg, (uint16_t)(off + 0x0A), 0);
        mem_write16(cpu, seg, (uint16_t)(off + 0x0C), 0);        /* no direct window func */
        mem_write16(cpu, seg, (uint16_t)(off + 0x0E), 0);
        mem_write16(cpu, seg, (uint16_t)(off + 0x10), VESA_WIDTH);
        mem_write16(cpu, seg, (uint16_t)(off + 0x12), VESA_WIDTH);
        mem_write16(cpu, seg, (uint16_t)(off + 0x14), VESA_HEIGHT);
        mem_write8(cpu, seg, (uint16_t)(off + 0x16), 8);         /* char cell */
        mem_write8(cpu, seg, (uint16_t)(off + 0x17), 16);
        mem_write8(cpu, seg, (uint16_t)(off + 0x18), 1);         /* planes */
        mem_write8(cpu, seg, (uint16_t)(off + 0x19), 8);         /* bits per pixel */
        mem_write8(cpu, seg, (uint16_t)(off + 0x1A), 1);         /* banks */
        mem_write8(cpu, seg, (uint16_t)(off + 0x1B), 4);         /* packed pixel */
        mem_write8(cpu, seg, (uint16_t)(off + 0x1C), 0);         /* bank size */
        mem_write8(cpu, seg, (uint16_t)(off + 0x1D), 0);         /* image pages */
        cpu->ax = 0x004F;
        break;
    }
    case 0x02:     /* set mode BX */
        if ((cpu->bx & 0x7FFF) == VESA_MODE) { vga_set_pitch(VESA_WIDTH); cpu->ax = 0x004F; }
        else cpu->ax = 0x014F;
        break;
    case 0x03:     /* get current mode */
        cpu->bx = VESA_MODE;
        cpu->ax = 0x004F;
        break;
    case 0x07:     /* set/get display start: BH=0 set, BH=1 get; CX=pixel, DX=scanline */
        if (cpu->bh == 1) { cpu->cx = g_vesa_start_x; cpu->dx = g_vesa_start_y; }
        else { g_vesa_start_x = cpu->cx; g_vesa_start_y = cpu->dx; }
        cpu->ax = 0x004F;
        break;
    case 0x05:     /* window control: BH=0 set / 1 get, BL=window, DX=position */
        if (cpu->bh == 1) cpu->dx = g_vesa_bank;
        else { g_vesa_bank = cpu->dx; vesa_set_bank(cpu, cpu->dx); }
        cpu->ax = 0x004F;
        break;
    default:
        TRACE("VESA %02X unimplemented\n", cpu->al);
        cpu->ax = 0x014F;   /* call failed */
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
    case 0x10:  /* palette / DAC */
        switch (cpu->al) {
        case 0x10:  /* set one DAC register: BX=index, DH=r, CH=g, CL=b */
            if (cpu->bx < 256) {
                g_dac[cpu->bx * 3 + 0] = cpu->dh;
                g_dac[cpu->bx * 3 + 1] = cpu->ch;
                g_dac[cpu->bx * 3 + 2] = cpu->cl;
            }
            break;
        case 0x12:  /* set a block: BX=first, CX=count, ES:DX=RGB triples */
            for (uint16_t i = 0; i < cpu->cx && (uint32_t)cpu->bx + i < 256; i++)
                for (int k = 0; k < 3; k++)
                    g_dac[(cpu->bx + i) * 3 + k] =
                        mem_read8(cpu, cpu->es, (uint16_t)(cpu->dx + i * 3 + k));
            break;
        case 0x15:  /* read one DAC register -> DH=r, CH=g, CL=b */
            if (cpu->bx < 256) {
                cpu->dh = g_dac[cpu->bx * 3 + 0];
                cpu->ch = g_dac[cpu->bx * 3 + 1];
                cpu->cl = g_dac[cpu->bx * 3 + 2];
            }
            break;
        case 0x17:  /* read a block */
            for (uint16_t i = 0; i < cpu->cx && (uint32_t)cpu->bx + i < 256; i++)
                for (int k = 0; k < 3; k++)
                    mem_write8(cpu, cpu->es, (uint16_t)(cpu->dx + i * 3 + k),
                               g_dac[(cpu->bx + i) * 3 + k]);
            break;
        default:
            TRACE("INT10 palette AL=%02X unimplemented\n", cpu->al);
            break;
        }
        break;
    case 0x12:  /* get EGA/VGA configuration */
        if (cpu->bl == 0x10) { cpu->bh = 0; cpu->bl = 3; cpu->cx = 0x0009; }
        break;
    case 0x4F:  vesa(cpu); break;   /* VESA super-VGA extensions */
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

/* ELFISH_KEYS feeds a scripted key sequence, because there is no window to type
 * into yet and the game only advances when something presses a key. Characters go
 * as-is; a backslash escape covers the ones you cannot put in an environment
 * variable: \r Enter, \e Esc, \n newline, \\ a backslash.
 * ELFISH_KEY_EVERY (default 400) is how many INT 16h polls to wait between them,
 * so the game finishes reacting to one before the next arrives. */
static int kb_scripted(void) {
    static const char *next;
    static long every, polls;
    if (!next) {
        const char *e = getenv("ELFISH_KEYS");
        next = e ? e : "";
        e = getenv("ELFISH_KEY_EVERY");
        every = e ? atol(e) : 400;
        if (every < 1) every = 1;
    }
    if (!*next || ++polls % every) return -1;
    int c = (unsigned char)*next++;
    if (c == '\\' && *next) {
        int esc = (unsigned char)*next++;
        c = esc == 'r' ? 13 : esc == 'n' ? 10 : esc == 'e' ? 27 : esc;
    }
    fprintf(stderr, "key %02X\n", c);
    return (c & 0xFF) | ((c & 0xFF) << 8);
}

static int kb_poll(void) {
    if (kb_pending >= 0) return kb_pending;
    int s = kb_scripted();
    if (s >= 0) return (kb_pending = s);
    if (!_kbhit()) return -1;
    int c = _getch();
    if (c == 0 || c == 0xE0) kb_pending = (_getch() & 0xFF) << 8;  /* AL=0, AH=scan */
    else kb_pending = (c & 0xFF) | ((c & 0xFF) << 8);              /* ascii in AL */
    return kb_pending;
}

void bios_int16(CPU *cpu)
{
    /* The program sits in this poll loop once it is up, and never returns to
     * main, so this is where a framebuffer dump can actually be taken. */
    { static long polls; const char *fb = getenv("ELFISH_DUMP_FB");
      const char *at = getenv("ELFISH_DUMP_AT");
      if (fb && ++polls == (at ? atol(at) : 20000)) elfish_dump_framebuffer(cpu, fb); }
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
/* ---- Mouse (INT 33h) ----
 * The reset call decides whether the game believes there is a mouse at all: it
 * wants AX=FFFF and a button count, and the old stub left AX at whatever the
 * caller had, which reads as "no mouse". A mouse-driven menu then never polls
 * for one. There is no window to take real movement from yet, so the pointer
 * sits still in the middle of the screen and no button is ever down.
 * ponytail: position is fixed until SDL provides a real one. */
static int g_mouse_x = VESA_WIDTH / 2, g_mouse_y = VESA_HEIGHT / 2, g_mouse_shown;

void mouse_int33(CPU *cpu)
{
    TRACE("INT33 ax=%04X\n", cpu->ax);
    switch (cpu->ax) {
    case 0x0000:   /* reset and detect */
        cpu->ax = 0xFFFF;   /* installed */
        cpu->bx = 2;        /* two buttons */
        g_mouse_shown = 0;
        break;
    case 0x0001: g_mouse_shown = 1; break;   /* show cursor */
    case 0x0002: g_mouse_shown = 0; break;   /* hide cursor */
    case 0x0003:   /* get position and buttons */
        cpu->bx = 0;                        /* nothing pressed */
        cpu->cx = (uint16_t)g_mouse_x;
        cpu->dx = (uint16_t)g_mouse_y;
        break;
    case 0x0004:   /* set position */
        g_mouse_x = cpu->cx; g_mouse_y = cpu->dx;
        break;
    case 0x0005: case 0x0006:   /* button press / release counts since last ask */
        cpu->ax = 0; cpu->bx = 0;
        cpu->cx = (uint16_t)g_mouse_x;
        cpu->dx = (uint16_t)g_mouse_y;
        break;
    default:
        /* Ranges, sensitivity, event handlers: accepted and ignored. */
        break;
    }
}
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
/* Free (ordinals 58 and 68). The selector arrives in AX; cpu_free_selector
 * ignores anything that is not a live dynamic selector, so the huge-block form
 * passing it elsewhere costs nothing. Startup allocates and frees the same
 * 256KB buffer over a thousand times, so this is not optional bookkeeping --
 * without it the heap is gone before the video init runs. */
void tsx_mem_free(CPU *cpu) {
    TRACE("tsx_mem_free ax=%04X\n", cpu->ax);
    cpu_free_selector(cpu, cpu->ax);
    cpu->sp += 4;
}
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
    /* AX is the size in paragraphs, same as the small form. It used to take a
     * flat 1MB regardless. */
    uint32_t bytes = (uint32_t)cpu->ax * 16u;
    if (bytes < 0x1000u) bytes = 0x1000u;
    uint16_t sel = cpu_alloc_selector(cpu, bytes);
    cpu->ax = 0;
    cpu->dx = sel;
    if (sel) cpu->flags &= ~FLAG_CF; else cpu->flags |= FLAG_CF;
    cpu->sp += 4;
}
void tsx_huge_free(CPU *cpu) {
    TRACE("tsx_huge_free ds=%04X si=%04X\n", cpu->ds, cpu->si);
    /* Callers pass the block as DS:SI with the paragraph count in AX; one passes
     * the selector in SI instead. Both are safe -- cpu_free_selector ignores
     * anything that is not a live dynamic selector. */
    cpu_free_selector(cpu, cpu->ds);
    cpu_free_selector(cpu, cpu->si);
    cpu->sp += 4;
}
/* TSXLIB ordinal 72 is DPMI "simulate real-mode interrupt", not a file create --
 * the ordinal map guessed wrong. It is how everything in this program reaches
 * the BIOS from protected mode. On entry DS:BX is a DPMI real-mode call
 * structure the caller has already filled in, AL is the interrupt number and CL
 * the DPMI flags -- the wrapper pops both off the stack into registers before
 * calling, so this is a plain RETF.
 *
 * Offsets are the DPMI ones: EDI 0x00, ESI 0x04, EBP 0x08, EBX 0x10, EDX 0x14,
 * ECX 0x18, EAX 0x1C, flags 0x20, ES 0x22, DS 0x24. DS and BX have to survive,
 * because the caller copies the results back out through them. */
void tsx_dpmi_int(CPU *cpu) {
    uint16_t intno = cpu->al;
    uint16_t sel = cpu->ds, rm = cpu->bx;
    TRACE("tsx_dpmi_int %02X ax=%04X\n", intno, mem_read16(cpu, sel, (uint16_t)(rm + 0x1C)));

    cpu->di = mem_read16(cpu, sel, (uint16_t)(rm + 0x00));
    cpu->si = mem_read16(cpu, sel, (uint16_t)(rm + 0x04));
    cpu->bp = mem_read16(cpu, sel, (uint16_t)(rm + 0x08));
    cpu->bx = mem_read16(cpu, sel, (uint16_t)(rm + 0x10));
    cpu->dx = mem_read16(cpu, sel, (uint16_t)(rm + 0x14));
    cpu->cx = mem_read16(cpu, sel, (uint16_t)(rm + 0x18));
    cpu->ax = mem_read16(cpu, sel, (uint16_t)(rm + 0x1C));
    cpu->es = mem_read16(cpu, sel, (uint16_t)(rm + 0x22));
    cpu->ds = mem_read16(cpu, sel, (uint16_t)(rm + 0x24));

    switch (intno) {
    case 0x21: dos_int21(cpu);   break;
    case 0x10: bios_int10(cpu);  break;
    case 0x16: bios_int16(cpu);  break;
    case 0x33: mouse_int33(cpu); break;
    default:   int_handler(cpu, intno); break;
    }

    mem_write16(cpu, sel, (uint16_t)(rm + 0x00), cpu->di);
    mem_write16(cpu, sel, (uint16_t)(rm + 0x04), cpu->si);
    mem_write16(cpu, sel, (uint16_t)(rm + 0x08), cpu->bp);
    mem_write16(cpu, sel, (uint16_t)(rm + 0x10), cpu->bx);
    mem_write16(cpu, sel, (uint16_t)(rm + 0x14), cpu->dx);
    mem_write16(cpu, sel, (uint16_t)(rm + 0x18), cpu->cx);
    mem_write16(cpu, sel, (uint16_t)(rm + 0x1C), cpu->ax);
    mem_write16(cpu, sel, (uint16_t)(rm + 0x20), cpu->flags);
    mem_write16(cpu, sel, (uint16_t)(rm + 0x22), cpu->es);
    mem_write16(cpu, sel, (uint16_t)(rm + 0x24), cpu->ds);

    cpu->ds = sel;
    cpu->bx = rm;
    cpu->sp += 4;   /* plain RETF -- the caller popped its own two words */
}
TSX_STUB(tsx_file_write)
TSX_STUB(tsx_file_seek)
