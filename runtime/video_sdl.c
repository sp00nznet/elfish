/*
 * video_sdl.c - A window for the framebuffer the game already draws into.
 *
 * The guest writes 8-bit pixels into a banked VESA window; tsxlib_stubs.c keeps
 * the whole of video memory behind it and hands the result here to be shown.
 * Input goes the other way: SDL events become BIOS keystrokes and a mouse
 * position that INT 16h and INT 33h read back, so the game is driven by the same
 * two interrupts it would use on real hardware.
 *
 * Built only when CMake finds SDL2. Without it every entry point here is a
 * no-op and the program still runs headless, which is what ELFISH_DUMP_FB and
 * ELFISH_KEYS exist for.
 */
#include "runtime_api.h"

#ifndef ELFISH_SDL

int  video_open(unsigned w, unsigned h) { (void)w; (void)h; return 0; }
void video_frame(const uint8_t *vram, const uint8_t *dac) { (void)vram; (void)dac; }
int  video_key(void) { return -1; }
void video_mouse(int *x, int *y, int *buttons) { (void)x; (void)y; (void)buttons; }
int  video_quit_requested(void) { return 0; }
void video_close(void) { }

#else

/* We keep our own main(), so SDL must not substitute its own. */
#define SDL_MAIN_HANDLED
#include <SDL2/SDL.h>
#include <string.h>
#include <stdio.h>

#define KEYQ 32

static SDL_Window   *g_win;
static SDL_Renderer *g_ren;
static SDL_Texture  *g_tex;
static unsigned      g_w, g_h;
static uint32_t     *g_pixels;          /* one ARGB frame */
static Uint32        g_last_present;
static int           g_quit;

static int g_keyq[KEYQ], g_keyq_head, g_keyq_tail;
static int g_mx, g_my, g_mb;

/* BIOS keystrokes are AH=scan, AL=ASCII. Only the keys a DOS menu actually
 * reads are mapped; anything else arrives as its ASCII through SDL_TEXTINPUT. */
static int bios_key(SDL_Keycode k, Uint16 mod)
{
    switch (k) {
    case SDLK_RETURN: case SDLK_KP_ENTER: return 0x1C0D;
    case SDLK_ESCAPE:                     return 0x011B;
    case SDLK_BACKSPACE:                  return 0x0E08;
    case SDLK_TAB:    return (mod & KMOD_SHIFT) ? 0x0F00 : 0x0F09;
    case SDLK_SPACE:                      return 0x3920;
    case SDLK_UP:     return 0x4800;
    case SDLK_DOWN:   return 0x5000;
    case SDLK_LEFT:   return 0x4B00;
    case SDLK_RIGHT:  return 0x4D00;
    case SDLK_HOME:   return 0x4700;
    case SDLK_END:    return 0x4F00;
    case SDLK_PAGEUP: return 0x4900;
    case SDLK_PAGEDOWN: return 0x5100;
    case SDLK_INSERT: return 0x5200;
    case SDLK_DELETE: return 0x5300;
    default: break;
    }
    if (k >= SDLK_F1 && k <= SDLK_F10)    /* F1..F10 are scan 0x3B..0x44 */
        return (0x3B + (k - SDLK_F1)) << 8;
    return -1;
}

static void push_key(int ax)
{
    int next = (g_keyq_head + 1) % KEYQ;
    if (next == g_keyq_tail) return;      /* full: drop, as the BIOS buffer does */
    g_keyq[g_keyq_head] = ax;
    g_keyq_head = next;
}

int video_open(unsigned w, unsigned h)
{
    if (g_win) return 1;
    SDL_SetMainReady();
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        fflush(stderr);
        return 0;
    }
    g_w = w; g_h = h;
    /* Open at 2x. The renderer's logical size keeps the guest's coordinates, so
     * a mouse position needs no scaling of its own. */
    g_win = SDL_CreateWindow("El-Fish (recompiled)",
                             SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                             (int)w * 2, (int)h * 2, SDL_WINDOW_RESIZABLE);
    if (!g_win) {
        fprintf(stderr, "SDL_CreateWindow failed: %s\n", SDL_GetError());
        fflush(stderr);
        return 0;
    }
    g_ren = SDL_CreateRenderer(g_win, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!g_ren) g_ren = SDL_CreateRenderer(g_win, -1, 0);
    if (!g_ren) return 0;
    SDL_RenderSetLogicalSize(g_ren, (int)w, (int)h);
    g_tex = SDL_CreateTexture(g_ren, SDL_PIXELFORMAT_ARGB8888,
                              SDL_TEXTUREACCESS_STREAMING, (int)w, (int)h);
    g_pixels = (uint32_t *)malloc((size_t)w * h * sizeof(uint32_t));
    SDL_StartTextInput();
    fprintf(stderr, "video: window %ux%u (%s)\n", w, h, SDL_GetCurrentVideoDriver());
    fflush(stderr);
    return g_tex && g_pixels;
}

static void pump(void)
{
    SDL_Event e;
    while (SDL_PollEvent(&e)) {
        switch (e.type) {
        case SDL_QUIT:
            g_quit = 1;
            break;
        case SDL_KEYDOWN: {
            int ax = bios_key(e.key.keysym.sym, e.key.keysym.mod);
            if (ax >= 0) push_key(ax);
            /* Ctrl-Q closes, since a DOS program has no reason to. */
            if (e.key.keysym.sym == SDLK_q && (e.key.keysym.mod & KMOD_CTRL))
                g_quit = 1;
            break;
        }
        case SDL_TEXTINPUT:
            /* Printable characters, with no scan code -- almost nothing reads
             * the scan code of a letter. */
            for (const char *p = e.text.text; *p; p++)
                if ((unsigned char)*p >= 0x20 && (unsigned char)*p < 0x7F)
                    push_key((unsigned char)*p);
            break;
        case SDL_MOUSEMOTION:
            g_mx = e.motion.x; g_my = e.motion.y;
            break;
        case SDL_MOUSEBUTTONDOWN:
        case SDL_MOUSEBUTTONUP:
            g_mx = e.button.x; g_my = e.button.y;
            g_mb = (e.button.state == SDL_PRESSED)
                 ? (g_mb | (e.button.button == SDL_BUTTON_LEFT ? 1 : 2))
                 : (g_mb & ~(e.button.button == SDL_BUTTON_LEFT ? 1 : 2));
            break;
        default: break;
        }
    }
}

void video_frame(const uint8_t *vram, const uint8_t *dac)
{
    if (!g_win) return;
    pump();
    /* Redrawing on every poll would be thousands of frames a second for a
     * picture that changes rarely; 60Hz is enough and leaves the CPU alone. */
    Uint32 now = SDL_GetTicks();
    if (now - g_last_present < 16) return;
    g_last_present = now;

    for (unsigned i = 0; i < g_w * g_h; i++) {
        const uint8_t *c = dac + (size_t)vram[i] * 3;
        /* The DAC holds 6-bit components, as VGA always has. */
        g_pixels[i] = 0xFF000000u | ((uint32_t)(c[0] << 2) << 16)
                                  | ((uint32_t)(c[1] << 2) << 8)
                                  |  (uint32_t)(c[2] << 2);
    }
    SDL_UpdateTexture(g_tex, NULL, g_pixels, (int)(g_w * sizeof(uint32_t)));
    SDL_RenderClear(g_ren);
    SDL_RenderCopy(g_ren, g_tex, NULL, NULL);
    SDL_RenderPresent(g_ren);
}

int video_key(void)
{
    if (!g_win || g_keyq_tail == g_keyq_head) return -1;
    int ax = g_keyq[g_keyq_tail];
    g_keyq_tail = (g_keyq_tail + 1) % KEYQ;
    return ax;
}

void video_mouse(int *x, int *y, int *buttons)
{
    if (!g_win) return;
    *x = g_mx; *y = g_my; *buttons = g_mb;
}

int video_quit_requested(void) { return g_quit; }

void video_close(void)
{
    if (!g_win) return;
    free(g_pixels); g_pixels = NULL;
    SDL_DestroyTexture(g_tex);
    SDL_DestroyRenderer(g_ren);
    SDL_DestroyWindow(g_win);
    g_win = NULL;
    SDL_Quit();
}

#endif /* ELFISH_SDL */
