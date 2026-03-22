# El-Fish Static Recompilation

Static recompilation of **El-Fish** (1993, AnimaTek/Maxis, DOS) v1.01 for Windows 11.

## Project Status: Lift Complete, Fixing Call Resolution

### What's Done
- Game files fully extracted (`game/ELFISH/` directory tree)
- Main executable (`ELFISH.EXE`) identified as **NE (New Executable)** format
- Built complete NE analysis and lifting toolchain (6 tools)
- Full disassembly: **772 functions**, **214,516 instructions** across 121 code segments
- Program architecture mapped — core math engine, UI/logic, system layer identified
- **All 121 code segments lifted to C** — **1,544 functions**, **110,174 lines** in `src/`
- **3,299 FPU memory operations** properly resolved with `seg:off` addresses
- Runtime headers: `cpu.h` (CPU + FPU state), `segments.h` (1,501 cross-segment prototypes)
- CMake build system with TSXLIB runtime stubs
- Compilation verified on non-FPU segments

### Current Issues (Blocking Compilation)
| Issue | Count | Root Cause |
|-------|-------|------------|
| Unresolved far calls | 2,391 | NE relocation chaining not followed — parser only records the head of each chain, missing all subsequent fixup locations |
| Indirect far calls | 195 | `call far [bp-N]` — function pointer calls through the stack |
| Data bytes in code | 705 | Data tables embedded between functions, decoded as instructions |
| Out-of-function jumps | 140 | Function boundary detection missed some cases |

**Root cause analysis:** NE relocations use a chained linked list. Each relocation record stores one offset (the head), and at that offset in the segment data, the bytes contain a pointer to the next location needing the same fixup, continuing until `0xFFFF` (end of chain). The current `ne_parse.py` only records the head offset, so ~60% of fixup locations are invisible to the lifter. Fix: walk each relocation chain through the segment data and record all offsets.

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
