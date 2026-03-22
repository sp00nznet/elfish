# El-Fish Code Segment Analysis

## Architecture Overview

121 code segments, 508KB total. All form one connected component.
Only ~12 segments directly call TSXLIB; the rest use internal cross-segment calls.

## Segment Categories (by function)

### Core Math / Fish Engine (FPU-heavy)
| Seg | Size | FPU ops | Role |
|-----|------|---------|------|
| 231 | 52,764 | 6,580 | Fish evolution/genetics engine (largest, self-recursive) |
| 230 | 47,944 | 7,341 | Fish rendering/animation |
| 229 | 34,525 | 2,869 | Physics/movement calculations |
| 228 | 26,899 | 956 | Fish shape generation |
| 225 | 18,406 | 2,371 | Rendering math (helper for seg 230) |

### Game Logic / UI
| Seg | Size | Role |
|-----|------|------|
| 227 | 25,777 | Main game logic/UI hub (most connections) |
| 226 | 18,922 | UI/display manager |
| 224 | 16,996 | Object/resource manager |
| 223 | 16,912 | Scene/aquarium manager |

### System Layer (TSXLIB wrappers)
| Seg | Size | Role |
|-----|------|------|
| 166 | 1,498 | Segment manager (all seg_call/seg_jmp) |
| 157 | 1,077 | File I/O wrapper |
| 151 | 790 | Memory management wrapper |
| 174 | 1,890 | System init, file create/write |
| 211 | 5,726 | Resource loader |
| 209 | 5,056 | Startup/main entry |
| 112 | 8,373 | Low-level runtime (port I/O, segs) |
| 122 | 131 | Entry point (jumps to seg 209) |

### Utility / Library Segments
- Segs 111-165 (small, <1.5KB each): utility functions, converters, helpers
- Segs 153, 155: string/data utilities (called by many segments)
- Seg 131: standalone math (no relocations)

## Statistics
- Total functions: 772 (697 far)
- Total instructions: 214,516
- FPU operations: ~21,252 (TSXLIB ordinals 22-24)
- System calls: 44 (TSXLIB ordinals 32-75)
- Internal cross-segment refs: 4,022
