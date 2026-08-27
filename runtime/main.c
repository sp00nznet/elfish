/*
 * main.c - El-Fish recomp runtime entry.
 *
 * Loads the flat memory image (segments + applied relocations), sets up the
 * initial CPU/segment state from the NE header, and calls the lifted entry
 * function (seg122_0000). This is the first real execution attempt; expect it
 * to fault or stall on unimplemented TSXLIB/DOS services - that is the signal
 * for what to implement next.
 */
#include "cpu.h"
#include "segments.h"
#include <stdio.h>
#include <stdlib.h>

#ifndef ELFISH_IMAGE_PATH
#define ELFISH_IMAGE_PATH "build_data/mem_image.bin"
#endif

static int load_image(CPU *cpu, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open image: %s\n", path);
        return 0;
    }
    size_t n = fread(cpu->mem, 1, ELFISH_IMAGE_SIZE, f);
    fclose(f);
    if (n != ELFISH_IMAGE_SIZE) {
        fprintf(stderr, "short read: %zu of %u\n", n, (unsigned)ELFISH_IMAGE_SIZE);
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    /* The -DELFISH_TRACE_FN trace is millions of lines; unbuffered stderr
     * makes it slower than the program. */
    setvbuf(stderr, NULL, _IOFBF, 1 << 20);

    const char *img = (argc > 1) ? argv[1] : ELFISH_IMAGE_PATH;

    CPU cpu;
    cpu_init(&cpu);

    /* Image + a heap for dynamic TSXLIB allocations (selectors past the image). */
    uint32_t total = ELFISH_IMAGE_SIZE + (128u << 20);  /* +128 MB heap */
    if (!cpu_alloc_mem(&cpu, total)) {
        fprintf(stderr, "Failed to allocate %u bytes\n", total);
        return 1;
    }
    if (!load_image(&cpu, img)) {
        cpu_free(&cpu);
        return 1;
    }

    /* Initial segment/register state from the NE header. */
    cpu.ss = ELFISH_STACK_SEG;
    cpu.sp = ELFISH_STACK_SP;
    cpu.ds = ELFISH_AUTO_DATA_SEG;
    cpu.es = ELFISH_AUTO_DATA_SEG;
    cpu.cs = ELFISH_ENTRY_SEG;

    /* The DOS extender publishes the framebuffer selector the video driver
     * later looks for; nothing in the lifted code does it for us. */
    elfish_video_init(&cpu);

    printf("El-Fish Recomp - starting\n");
    printf("  image: %s (%.2f MB)\n", img, ELFISH_IMAGE_SIZE / 1048576.0);
    printf("  entry: seg%u:%04X  stack: seg%u:%04X\n",
           ELFISH_ENTRY_SEG, ELFISH_ENTRY_IP, ELFISH_STACK_SEG, ELFISH_STACK_SP);
    fflush(stdout);

    seg122_0000(&cpu);  /* NE entry point */

    /* ELFISH_DUMP_FB=<path> writes what the game drew, so there is something to
     * look at before there is a window to look at it in. */
    { const char *fb = getenv("ELFISH_DUMP_FB");
      if (fb) elfish_dump_framebuffer(&cpu, fb); }

    printf("entry returned (ax=%04X)\n", cpu.ax);
    cpu_free(&cpu);
    return 0;
}
