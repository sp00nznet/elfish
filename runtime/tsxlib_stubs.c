/*
 * tsxlib_stubs.c - TSXLIB Runtime Stubs for El-Fish Recomp
 *
 * Placeholder implementations for AnimaTek's TSXLIB protected-mode
 * runtime functions. These will be replaced with proper implementations
 * as the recomp progresses.
 */

#include "cpu.h"
#include <stdio.h>

void tsx_desc_alloc(CPU *cpu)
{
    fprintf(stderr, "STUB: tsx_desc_alloc(ax=0x%04X)\n", cpu->ax);
}

void tsx_dos_call(CPU *cpu)
{
    fprintf(stderr, "STUB: tsx_dos_call(ax=0x%04X, bx=0x%04X)\n", cpu->ax, cpu->bx);
}

void tsx_file_close(CPU *cpu)
{
    fprintf(stderr, "STUB: tsx_file_close(bx=0x%04X)\n", cpu->bx);
}
