# El-Fish Static Recompilation

Static recompilation of **El-Fish** (1993, AnimaTek/Maxis, DOS) v1.01 for Windows 11.

## Project Status: Executes Startup Code

The full lifted codebase **compiles, links (zero undefined symbols), and runs**: it loads a
flat memory image, calls the NE entry point, flows across segments
(`seg122 → seg209_0196 → seg209_0306`), issues a DOS `INT 21h` call, and returns without
faulting. Focus is now on **runtime services** so startup can proceed into the game.

### What's Done
- Game files fully extracted (`game/ELFISH/` directory tree)
- Main executable (`ELFISH.EXE`) identified as **NE (New Executable)** format
- Built complete NE analysis and lifting toolchain (8 tools)
- Program architecture mapped — core math engine, UI/logic, system layer identified
- **All 121 code segments lifted to C** — **2,236 functions**, ~**196K lines** in `src/`
- **Relocation chaining fixed** — far-call resolution went from 4,966 unresolved to **2** (99.96%)
- **IDA-driven disassembly** — IDA Professional 9.1 (idalib, headless) exports accurate
  function boundaries + instruction heads (`analysis/ida_funcs.json`); the decoder syncs to
  these, cutting unaligned NO-OP stubs from **819 → 26** (96.8%)
- **Cross-segment entry-point seeding** — function detection seeds from prologues + near-call
  targets + far-call targets + IDA functions, so call destinations become real functions
- Runtime: `cpu.h` (CPU + FPU state), `runtime_api.h` (interrupt + TSXLIB ordinal decls),
  `tsxlib_stubs.c` (all 33 ordinals + interrupt handlers stubbed), auto-generated `segments.h`
- CMake/Ninja build → `libelfish_segments.a` + `libelfish_runtime.a` + `elfish_test.exe`,
  verified link-clean (whole-archive, 0 undefined symbols)

### Remaining Work (correctness, prioritized)
| Issue | Count | Status / Plan |
|-------|-------|---------------|
| Runtime services are no-ops | — | **Next.** Startup reaches DOS `INT 21h AH=51h` then early-exits; implement TSXLIB mem/file + DOS/BIOS services so init proceeds |
| Dropped opcodes (`rcr`/`rcl` + others) | ~300 | Emitted as TODO comments; implement in `lift16.py` |
| Indirect far calls/jumps | ~200 | `call/jmp far [mem]` function-pointer dispatch, unhandled |
| Unaligned NO-OP stubs (residual) | 26 | Bogus far-call targets past segment end / IDA-classified data — no-op is correct |

**Memory model:** selectors are normalized to NE segment indices; `gen_image.py` builds a flat
image (`build_data/mem_image.bin`) placing each segment at `SEG_SEGMENT_BASE[n]` with all 12,320
internal relocations applied. `seg_off()` translates selector→base at runtime; unmapped selectors
hit an isolated guard region.

**Relocation chaining (fixed):** NE relocations are a chained linked list — each record stores
only the head offset, and the pre-relocation word at each fixup location points to the next
location needing the same fixup, until `0xFFFF`. `build_reloc_map` now walks the full chain
through segment data (non-additive relocations), recovering all fixup sites.

### Executable Analysis

| Metric | Value |
|--------|-------|
| Format | NE (16-bit segmented), self-loading protected mode |
| File size | 797,592 bytes |
| Code segments | 121 (508 KB total code) |
| Data segments | 110 |
| Functions detected | 772 (697 far) |
| Instructions | 214,516 |
| Relocations | 25,394 (4,022 internal, 21,372 imports) |
| Runtime | TSXLIB v5.10 (AnimaTek's protected-mode DOS runtime) |
| TSXLIB ordinals used | 33 unique (21K+ call sites) |

### Program Architecture

Only 12 of 121 code segments directly call TSXLIB — the system layer is thin and well-contained.

**Core Math / Fish Engine** (FPU-heavy, ~175KB):
| Seg | Size | FPU ops | Role |
|-----|------|---------|------|
| 231 | 53KB | 6,580 | Fish evolution/genetics (self-recursive, largest function 5.6KB) |
| 230 | 48KB | 7,341 | Fish rendering/animation |
| 229 | 35KB | 2,869 | Physics/movement calculations |
| 228 | 27KB | 956 | Fish shape generation |
| 225 | 18KB | 2,371 | Rendering math helper |

**Game Logic / UI** (~78KB):
| Seg | Size | Role |
|-----|------|------|
| 227 | 26KB | Main game logic/UI hub (most cross-segment connections) |
| 226 | 19KB | UI/display manager |
| 224 | 17KB | Object/resource manager |
| 223 | 17KB | Scene/aquarium manager |

**System Layer** (TSXLIB wrappers, ~25KB):
| Seg | Size | Role |
|-----|------|------|
| 166 | 1.5KB | Segment manager |
| 157 | 1KB | File I/O wrapper |
| 151 | 790B | Memory management |
| 211 | 5.7KB | Resource loader |
| 209 | 5KB | Startup/main entry |
| 112 | 8.4KB | Low-level runtime |

### TSXLIB Runtime API

99.4% of TSXLIB imports are FPU emulation trampolines (ordinals 22-24). Only 44 actual system calls across these categories:
- **FPU emulation** (22-24): 21,252 call sites — translates to native C `double` ops
- **Memory management** (55-68): `malloc`/`free`/`realloc`/`lock` equivalents
- **File I/O** (36-75): `open`/`read`/`write`/`close`/`seek`
- **Segment management** (20-31): Protected-mode segment loading
- **System** (32-49): DOS interrupt dispatch, interrupt handlers, port I/O

### Lifted Code Stats

| Metric | Value |
|--------|-------|
| Source files | 121 (one per code segment) |
| Functions | 1,544 (1,501 with prototypes) |
| Lines of C | 110,174 |
| FPU memory ops resolved | 3,299 / 3,401 (97%) |
| Lifting errors | 0 |

### Building

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### What's Next
1. **Fix relocation chaining** in `ne_parse.py` — walk linked lists through segment data to capture all fixup offsets (~2,391 unresolved far calls)
2. **Re-lift all segments** with fixed relocations
3. Handle indirect far calls (195), data-in-code (705), and boundary misses (140)
4. Implement TSXLIB runtime stubs (memory alloc, file I/O, DOS compat)
5. Extract and load NE data segments into flat memory
6. Add SDL2 platform layer for video output and input
7. Test execution starting from entry point (seg 122 → seg 209)

### Other Executables

| File | Size | Format | Purpose |
|------|------|--------|---------|
| `ELFISH.EXE` | 798 KB | NE | Main application |
| `VIEWER.EXE` | 318 KB | NE | Tank/aquarium viewer |
| `PCONVERT.EXE` | 112 KB | NE | Palette converter |
| `AUTODEMO.EXE` | 25 KB | MZ | Auto-demo TSR |
| `MCONVERT.EXE` | 64 KB | MZ | Converter utility |
| `XX_MDR*.DLL` | 11-18 KB | Custom | Sound/video drivers |

## Game Technical Details
- 16-bit DOS, protected mode via TSXLIB, requires 386+, 4MB RAM
- VGA (376×348) and SVGA (640×400) via VESA 1.2
- Sound: AdLib, Sound Blaster, SB Pro, Roland MT-32, Pro Audio Spectrum, PC Speaker
- Custom DLL system for sound/video drivers (`XX_MDR*.DLL`, `*.MIR`)
- Install layout: `ARTWORK\`, `FISH\`, `SYSTEM\`, `AQUARIUM\`

## Project Structure
```
src/           — 121 lifted C source files (one per code segment)
runtime/
  cpu.h        — CPU + FPU state, memory access, flags, condition codes
  segments.h   — 1,501 cross-segment function prototypes (auto-generated)
  main.c       — Entry point (placeholder)
  tsxlib_stubs.c — TSXLIB runtime stub implementations
tools/
  ne_parse.py  — NE executable format parser
  ne_decode.py — NE-aware disassembler with x87 FPU decoding
  ne_lift.py   — NE-aware x86-to-C lifter with FPU support
  fpu_decode.py — Full x87 FPU instruction decoder
  tsxlib.py    — TSXLIB ordinal-to-C function mapping
  ne_xref.py   — Cross-reference and call graph builder
analysis/      — Generated analysis outputs
CMakeLists.txt — Build system
```

## Toolchain
Uses [pcrecomp](https://github.com/sp00nznet/pcrecomp) as the base 16-bit recompilation pipeline, extended with NE format support:
- `decode16.py` — 16-bit x86 instruction decoder (pcrecomp)
- `lift16.py` — Base x86-to-C lifter (pcrecomp)
- `ne_*.py` / `fpu_decode.py` / `tsxlib.py` — NE format extensions (this project)
- `recomp16/` — Runtime library (pcrecomp, to be adapted)

## Related
- [pcrecomp tools](https://github.com/sp00nznet/pcrecomp) — Static recompilation toolbox
- Civilization recomp (similar 16-bit DOS, 1991) — reference project, reached 482 functions / 132K lines
