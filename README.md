# El-Fish Static Recompilation

Static recompilation of **El-Fish** (1993, AnimaTek/Maxis, DOS) v1.01 for Windows 11.

## Project Status: Early Stage - Disk Extraction

### What's Done
- Sourced El-Fish v1.01 (4x 1.44MB floppy disk images)
- Extracted all 4 `.ima` floppy images to individual disk folders
- Merged all disk contents into a unified working set
- Analyzed the installer script (`INSTALL.PRG`) and packing manifest (`ELFISH.PKD`)
- Identified the custom AnimaTek packing format used by `INSTALL.EXE`:
  - Packed files use `.$XX` extensions (numbered parts)
  - Each packed file has a `1a 3c` magic header + destination filename + compressed data
  - `ELFISH.PKD` is a binary manifest mapping packed sources to install directories

### Current Blocker
The game files are stored in AnimaTek's custom compressed packing format. The installer (`INSTALL.EXE`) is needed to unpack them. Two approaches under investigation:
1. **DOSBox-X** - Run the original DOS installer (DOSBox-X installed at `C:\DOSBox-X`)
2. **Format reverse-engineering** - Decode the `1a 3c` pack format directly

### What's Next
1. Extract game files (via DOSBox-X installer or custom unpacker)
2. Identify and analyze main `ELFISH.EXE` executable
3. Run `decode16.py` + `analyze.py` from [pcrecomp](https://github.com/sp00nznet/pcrecomp) toolchain
4. Begin lifting 16-bit x86 functions to C
5. Build with SDL2 platform layer using recomp16 runtime

## Game Technical Details
- 16-bit DOS (MZ executable), requires 386+, 4MB RAM
- VGA (376x348) and SVGA (640x400) via VESA 1.2
- Sound: AdLib, Sound Blaster, SB Pro, Roland MT-32, Pro Audio Spectrum, PC Speaker
- Custom DLL system for sound/video drivers (`XX_MDR*.DLL`, `*.MIR`)
- Install layout: `ARTWORK\`, `FISH\`, `SYSTEM\`, `AQUARIUM\`, `SOUND\`

## El-Fish Disk Contents
| Disk | Key Files |
|------|-----------|
| 1 | `INSTALL.EXE`, `INSTALL.PRG`, `ELFISH.PKD`, `INFO.EXE`, `READ.ME` |
| 1-4 | `DATA\` folder with `.$XX` packed parts (ELFISH, VIEWER, PCONVERT, drivers, fish/art/sound assets) |

## Tools
Uses the [pcrecomp](https://github.com/sp00nznet/pcrecomp) 16-bit DOS recompilation pipeline:
- `decode16.py` - Disassemble and decode 16-bit MZ executables
- `analyze.py` - Analyze control flow and identify functions
- `lift16.py` - Lift x86 assembly to C source
- `recomp16/` - Runtime library (cpu.h, dos_compat.c, HAL, SDL2 platform)

## Related
- [pcrecomp tools](https://github.com/sp00nznet/pcrecomp) - Static recompilation toolbox
- Civilization recomp (similar 16-bit DOS, 1991) used as reference - reached 482 functions, 132K lines
