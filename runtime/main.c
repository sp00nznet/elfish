/*
 * main.c - El-Fish Recomp test entry point
 *
 * Placeholder for testing compilation of the lifted code.
 * Eventually this will set up the CPU state, load game data,
 * initialize SDL2, and call the entry point (seg122_0000).
 */

#include "cpu.h"
#include "segments.h"
#include <stdio.h>

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    CPU cpu;
    cpu_init(&cpu);

    if (!cpu_alloc_mem(&cpu, 16 * 1024 * 1024)) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    printf("El-Fish Recomp - compilation test\n");
    printf("CPU initialized, %u MB memory allocated\n", cpu.mem_size / (1024 * 1024));
    printf("FPU stack: %d registers, control=0x%04X\n", FPU_STACK_SIZE, cpu.fpu_control);
    printf("Ready to run %d segments\n", 121);

    /* TODO: Load game data, set up segments, call seg122_0000(&cpu) */

    cpu_free(&cpu);
    return 0;
}
