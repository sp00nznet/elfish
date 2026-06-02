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
void dos_int21(CPU *cpu)   { TRACE("INT21 ah=%02X\n", cpu->ah); (void)cpu; }
void bios_int10(CPU *cpu)  { TRACE("INT10 ah=%02X\n", cpu->ah); (void)cpu; }
void bios_int16(CPU *cpu)  { TRACE("INT16 ah=%02X\n", cpu->ah); (void)cpu; }
void mouse_int33(CPU *cpu) { TRACE("INT33 ax=%04X\n", cpu->ax); (void)cpu; }
void int_handler(CPU *cpu, int int_num) { TRACE("INT %02X\n", int_num); (void)cpu; (void)int_num; }

/* ---- TSXLIB ordinals ---- */
#define TSX_STUB(name) void name(CPU *cpu) { TRACE("%s\n", #name); (void)cpu; }
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
TSX_STUB(tsx_huge_alloc)
TSX_STUB(tsx_huge_free)
TSX_STUB(tsx_file_create)
TSX_STUB(tsx_file_write)
TSX_STUB(tsx_file_seek)
