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

/* Flip to 1 to trace every runtime call while bringing the program up. */
#ifndef ELFISH_TRACE_RUNTIME
#define ELFISH_TRACE_RUNTIME 0
#endif

#if ELFISH_TRACE_RUNTIME
#define TRACE(...) fprintf(stderr, __VA_ARGS__)
#else
#define TRACE(...) ((void)0)
#endif

/* ---- Software interrupts ---- */
void dos_int21(CPU *cpu)
{
    TRACE("INT21 ah=%02X al=%02X\n", cpu->ah, cpu->al);
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
    default:
        TRACE("INT21 ah=%02X UNHANDLED\n", cpu->ah);
        break;
    }
}
void bios_int10(CPU *cpu)  { TRACE("INT10 ah=%02X\n", cpu->ah); (void)cpu; }
void bios_int16(CPU *cpu)  { TRACE("INT16 ah=%02X\n", cpu->ah); (void)cpu; }
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
TSX_STUB(tsx_dos_call)
TSX_STUB(tsx_file_getinfo)
TSX_STUB(tsx_file_read)
TSX_STUB(tsx_file_close)
TSX_STUB(tsx_int_io)
TSX_STUB(tsx_set_handler)
TSX_STUB(tsx_save_context)
TSX_STUB(tsx_mem_alloc)
TSX_STUB(tsx_mem_alloc_small)
TSX_STUB(tsx_mem_free)
TSX_STUB(tsx_file_open)
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
