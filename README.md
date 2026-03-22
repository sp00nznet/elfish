# El-Fish Static Recompilation

Static recompilation of **El-Fish** (1993, AnimaTek/Maxis, DOS) v1.01 for Windows 11.

## Project Status: NE Executable Analysis

### What's Done
- Game files fully extracted (`game/ELFISH/` directory tree)
- Main executable (`ELFISH.EXE`) identified as **NE (New Executable)** format
- Built custom NE parser (`tools/ne_parse.py`) — segments, relocations, entries, imports
- Built NE-aware disassembler (`tools/ne_decode.py`) wrapping pcrecomp's decode16
- Full disassembly pass complete: **772 functions**, **214,516 instructions** across 121 code segments

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
| Runtime | TSXLIB (AnimaTek's protected-mode DOS runtime) |
| TSXLIB ordinals used | 33 unique (21K+ call sites) |
| FPU usage | Heavy — ordinals 22-24 are FPU emulation trampolines |

### Key Findings
- **NE format, not MZ** — El-Fish uses a segmented NE executable with a 22KB TSXLIB MZ stub as the protected-mode loader. This differs from Civ's MZ+overlay approach and required building a new toolchain.
- **TSXLIB runtime** — AnimaTek's proprietary DOS extender providing memory management, file I/O, and FPU emulation. 33 API functions used via import-by-ordinal relocations.
- **Heavy floating-point math** — The largest code segments are dominated by FPU operations (fish physics, evolution, rendering). TSXLIB provides FPU emulation for 386 systems without a 387 coprocessor. These translate directly to C `double` operations.
- **Largest function** — `seg231_AF1C` at 5.6KB with a 7.8KB stack frame, likely the core fish evolution/genetics algorithm.

### Other Executables

| File | Size | Format | Purpose |
|------|------|--------|---------|
| `ELFISH.EXE` | 798 KB | NE | Main application |
| `VIEWER.EXE` | 318 KB | NE | Tank/aquarium viewer |
| `PCONVERT.EXE` | 112 KB | NE | Palette converter |
| `AUTODEMO.EXE` | 25 KB | MZ | Auto-demo TSR |
| `MCONVERT.EXE` | 64 KB | MZ | Converter utility |
| `XX_MDR*.DLL` | 11-18 KB | Custom | Sound/video drivers |

### What's Next
1. Map TSXLIB ordinals to C runtime function signatures
2. Build cross-reference graph (call graph between segments)
3. Improve function boundary detection for non-standard prologues
4. Begin lifting x86 functions to C, starting with utilities
5. Create build system and TSXLIB runtime stubs
6. Target SDL2 platform layer for Windows 11

## Game Technical Details
- 16-bit DOS, protected mode via TSXLIB, requires 386+, 4MB RAM
- VGA (376×348) and SVGA (640×400) via VESA 1.2
- Sound: AdLib, Sound Blaster, SB Pro, Roland MT-32, Pro Audio Spectrum, PC Speaker
- Custom DLL system for sound/video drivers (`XX_MDR*.DLL`, `*.MIR`)
- Install layout: `ARTWORK\`, `FISH\`, `SYSTEM\`, `AQUARIUM\`

## Project Tools
- `tools/ne_parse.py` — NE executable format parser
- `tools/ne_decode.py` — NE-aware 16-bit disassembler
- `analysis/` — Generated analysis outputs (function lists, header dumps)

## Toolchain
Uses [pcrecomp](https://github.com/sp00nznet/pcrecomp) as the base 16-bit recompilation pipeline, extended with NE format support:
- `decode16.py` — 16-bit x86 instruction decoder (pcrecomp)
- `ne_parse.py` / `ne_decode.py` — NE format extensions (this project)
- `lift16.py` — x86-to-C lifter (pcrecomp, to be adapted for NE)
- `recomp16/` — Runtime library (pcrecomp)

## Related
- [pcrecomp tools](https://github.com/sp00nznet/pcrecomp) — Static recompilation toolbox
- Civilization recomp (similar 16-bit DOS, 1991) — reference project, reached 482 functions / 132K lines
