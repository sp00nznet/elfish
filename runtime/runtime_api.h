/*
 * runtime_api.h - Host runtime entry points referenced by lifted code.
 *
 * Interrupt handlers (emitted by the base lifter for `int N`) and TSXLIB
 * ordinal trampolines (emitted by ne_lift for resolved imports). Stub
 * implementations live in tsxlib_stubs.c until replaced with real behavior.
 */
#ifndef ELFISH_RUNTIME_API_H
#define ELFISH_RUNTIME_API_H

#include "cpu.h"

/* ---- Indirect call dispatchers (function pointers) ---- */
void dispatch_far(CPU *cpu, uint16_t seg, uint16_t off);
void dispatch_near(CPU *cpu, uint16_t seg, uint16_t off);

/* ---- Divide by zero ----
 * The lifter guards every div/idiv with this instead of letting C divide by
 * zero (undefined behaviour, SIGFPE on x86). On the real 386 this raises #DE;
 * here it reports the site and leaves the quotient/remainder registers alone,
 * so a stray zero divisor shows up as a diagnostic rather than a crash with no
 * context. ponytail: no INT 0 vectoring -- add it if the game installs a #DE
 * handler and depends on it. */
void catz_div0(const char *op);

/* ---- Software interrupts ---- */
void dos_int21(CPU *cpu);
void bios_int10(CPU *cpu);
void bios_int16(CPU *cpu);
void mouse_int33(CPU *cpu);
void int_handler(CPU *cpu, int int_num);

/* ---- TSXLIB ordinals (AnimaTek protected-mode runtime) ---- */
void tsx_fpu_dispatch(CPU *cpu);
void tsx_fpu_wait(CPU *cpu);
void tsx_fpu_memop(CPU *cpu);
void tsx_init_3(CPU *cpu);
void tsx_init_4(CPU *cpu);
void tsx_init_14(CPU *cpu);
void tsx_seg_load(CPU *cpu);
void tsx_seg_unload(CPU *cpu);
void tsx_seg_call(CPU *cpu);
void tsx_seg_jmp(CPU *cpu);
void tsx_seg_ref(CPU *cpu);
void tsx_seg_fixup_call(CPU *cpu);
void tsx_seg_fixup_jmp(CPU *cpu);
void tsx_dos_call(CPU *cpu);
void tsx_file_getinfo(CPU *cpu);
void tsx_file_read(CPU *cpu);
void tsx_file_close(CPU *cpu);
void tsx_int_io(CPU *cpu);
void tsx_set_handler(CPU *cpu);
void tsx_save_context(CPU *cpu);
void tsx_mem_alloc(CPU *cpu);
void tsx_mem_alloc_small(CPU *cpu);
void tsx_mem_free(CPU *cpu);
void tsx_file_open(CPU *cpu);
void tsx_mem_realloc(CPU *cpu);
void tsx_mem_lock(CPU *cpu);
void tsx_desc_alloc(CPU *cpu);
void tsx_desc_get_base(CPU *cpu);
void tsx_huge_alloc(CPU *cpu);
void tsx_huge_free(CPU *cpu);
void tsx_dpmi_int(CPU *cpu);   /* ordinal 72: DPMI real-mode interrupt */
void tsx_file_write(CPU *cpu);
void tsx_file_seek(CPU *cpu);

#endif /* ELFISH_RUNTIME_API_H */
