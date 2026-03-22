"""
ne_decode.py - NE-aware 16-bit Disassembler for El-Fish Recomp

Disassembles all code segments from an NE executable, resolving
relocation targets to provide cross-segment call/data annotations.

Usage:
    python ne_decode.py <ne_exe> [--seg N] [--summary] [--functions]
"""

import sys
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

# Add pcrecomp tools to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'tools', 'tools', 'disasm'))
sys.path.insert(0, os.path.dirname(__file__))

from decode16 import Decoder, Instruction, OpType, Operand
from ne_parse import parse_ne, NEHeader, Segment, Relocation
from fpu_decode import decode_fpu, format_fpu


@dataclass
class RelocAnnotation:
    """Annotation for a relocation fixup at a specific offset."""
    offset: int              # Offset within segment
    reloc: Relocation        # The relocation entry
    target_desc: str = ''    # Human-readable description


@dataclass
class NEFunction:
    """A detected function within an NE code segment."""
    seg_num: int            # 1-based segment number
    offset: int             # Offset within segment
    end: int                # End offset (exclusive)
    size: int = 0
    is_far: bool = False    # Uses RETF
    local_size: int = 0     # Stack frame size
    calls: list = field(default_factory=list)       # (seg, off) near/far call targets
    far_calls: list = field(default_factory=list)    # (target_seg, target_off) via relocation
    inst_count: int = 0

    @property
    def label(self):
        return f"seg{self.seg_num:03d}_{self.offset:04X}"


def build_reloc_map(seg: Segment, ne: NEHeader) -> dict:
    """Build a map of offset -> RelocAnnotation for a segment."""
    reloc_map = {}
    for r in seg.relocations:
        target_type = r.flags & 3
        if target_type == 0:  # Internal
            if r.target_seg == 0xFF:
                desc = f"entry#{r.ordinal}"
            else:
                target_seg = ne.segments[r.target_seg - 1] if r.target_seg <= len(ne.segments) else None
                if target_seg:
                    seg_type = 'CODE' if target_seg.is_code else 'DATA'
                    desc = f"seg{r.target_seg}:{r.target_off:04X} ({seg_type})"
                else:
                    desc = f"seg{r.target_seg}:{r.target_off:04X}"
        elif target_type == 1:  # Import by ordinal
            mod_name = ne.module_names[r.module_idx - 1] if r.module_idx <= len(ne.module_names) else f"mod{r.module_idx}"
            desc = f"{mod_name}.{r.ordinal}"
        elif target_type == 2:  # Import by name
            mod_name = ne.module_names[r.module_idx - 1] if r.module_idx <= len(ne.module_names) else f"mod{r.module_idx}"
            desc = f"{mod_name}@{r.ordinal}"
        else:
            desc = f"OSFIXUP({r.target_seg},{r.target_off})"

        src_name = r.src_name
        ann = RelocAnnotation(offset=r.offset, reloc=r, target_desc=f"[{src_name}] {desc}")
        reloc_map[r.offset] = ann

    return reloc_map


def detect_functions(seg: Segment, instructions: list) -> list:
    """Detect function boundaries using prologue/epilogue patterns."""
    functions = []
    current_func = None

    for i, inst in enumerate(instructions):
        local_off = inst.offset - seg.file_offset

        # Detect prologue: PUSH BP
        if (inst.mnemonic == 'push' and inst.op1 and
                inst.op1.type == OpType.REG16 and inst.op1.reg == 5):  # BP
            # Check if next is MOV BP, SP
            if i + 1 < len(instructions):
                next_inst = instructions[i + 1]
                if (next_inst.mnemonic == 'mov' and
                        next_inst.op1 and next_inst.op1.type == OpType.REG16 and next_inst.op1.reg == 5 and
                        next_inst.op2 and next_inst.op2.type == OpType.REG16 and next_inst.op2.reg == 4):
                    # Found prologue: push bp / mov bp, sp
                    if current_func:
                        current_func.end = local_off
                        current_func.size = current_func.end - current_func.offset
                        functions.append(current_func)

                    current_func = NEFunction(
                        seg_num=seg.index,
                        offset=local_off,
                        end=0,
                    )

                    # Check for SUB SP, N
                    if i + 2 < len(instructions):
                        sub_inst = instructions[i + 2]
                        if (sub_inst.mnemonic == 'sub' and
                                sub_inst.op1 and sub_inst.op1.type == OpType.REG16 and sub_inst.op1.reg == 4 and
                                sub_inst.op2 and sub_inst.op2.type in (OpType.IMM8, OpType.IMM16)):
                            current_func.local_size = sub_inst.op2.disp

        # Detect epilogue: RET / RETF
        if inst.mnemonic in ('ret', 'retf', 'iret'):
            if current_func:
                if inst.mnemonic == 'retf':
                    current_func.is_far = True
                current_func.inst_count += 1  # Count this one too
                current_func.end = local_off + inst.length
                current_func.size = current_func.end - current_func.offset
                functions.append(current_func)
                current_func = None
                continue

        if current_func:
            current_func.inst_count += 1

    # Handle unterminated function at end of segment
    if current_func:
        current_func.end = seg.actual_size
        current_func.size = current_func.end - current_func.offset
        functions.append(current_func)

    return functions


def disassemble_segment(seg: Segment, ne: NEHeader, show_relocs: bool = True) -> tuple:
    """Disassemble a code segment. Returns (instructions, functions, reloc_map)."""
    if not seg.data or not seg.is_code:
        return [], [], {}

    reloc_map = build_reloc_map(seg, ne)
    decoder = Decoder(seg.data, base_offset=seg.file_offset)
    instructions = decoder.decode_all()

    # Post-process: enhance FPU instructions with proper mnemonics
    # The base decoder's ESC handler reads ModR/M to advance position but
    # doesn't store the result. We re-decode it here from raw bytes.
    EA_BASES = [
        ('bx', 'si'), ('bx', 'di'), ('bp', 'si'), ('bp', 'di'),
        ('si', ''),   ('di', ''),   ('bp', ''),   ('bx', ''),
    ]
    EA_DEFAULT_SEG = ['ds', 'ds', 'ss', 'ss', 'ds', 'ds', 'ss', 'ds']

    for inst in instructions:
        if inst.mnemonic.startswith('esc_') or inst.mnemonic.startswith('fpu_'):
            raw = inst.raw
            skip = 0
            seg_override = ''
            if raw[0] in (0x26, 0x2E, 0x36, 0x3E):
                seg_override = {0x26: 'es', 0x2E: 'cs', 0x36: 'ss', 0x3E: 'ds'}[raw[0]]
                skip = 1
            if skip < len(raw) - 1 and 0xD8 <= raw[skip] <= 0xDF:
                opcode = raw[skip]
                modrm = raw[skip + 1]
                mod = (modrm >> 6) & 3
                reg = (modrm >> 3) & 7
                rm = modrm & 7

                # Re-decode ModR/M to build memory operand for the lifter
                mem_op = None
                if mod != 3:  # Memory operand
                    base_r, idx_r = EA_BASES[rm]
                    disp = 0
                    seg_name = seg_override

                    if mod == 0 and rm == 6:
                        # Direct address [disp16]
                        disp = int.from_bytes(raw[skip+2:skip+4], 'little', signed=True)
                        base_r = ''
                        idx_r = ''
                        if not seg_name: seg_name = 'ds'
                    elif mod == 1:
                        disp = raw[skip+2] if raw[skip+2] < 128 else raw[skip+2] - 256
                    elif mod == 2:
                        disp = int.from_bytes(raw[skip+2:skip+4], 'little', signed=True)

                    if not seg_name:
                        seg_name = EA_DEFAULT_SEG[rm] if not (mod == 0 and rm == 6) else 'ds'

                    mem_op = Operand(
                        type=OpType.MEM,
                        base=base_r,
                        index=idx_r,
                        disp=disp,
                        seg=seg_name,
                        size=2,  # Size doesn't matter for FPU; lifter uses operand_str
                    )

                mem_str = repr(mem_op) if mem_op else ''
                fpu = decode_fpu(opcode, modrm, mod, reg, rm, mem_str)
                inst.mnemonic = format_fpu(fpu)
                inst.op1 = mem_op  # Set to decoded memory operand or None for register ops
                inst.op2 = None

    functions = detect_functions(seg, instructions)

    return instructions, functions, reloc_map


def print_segment_disasm(seg: Segment, ne: NEHeader):
    """Print annotated disassembly for a single segment."""
    instructions, functions, reloc_map = disassemble_segment(seg, ne)

    # Build function start map for labels
    func_starts = {f.offset: f for f in functions}

    print(f"\n; === Segment {seg.index} ({seg.type_str}) ===")
    print(f"; File offset: 0x{seg.file_offset:08X}")
    print(f"; Size: 0x{seg.actual_size:04X} ({seg.actual_size} bytes)")
    print(f"; Relocations: {len(seg.relocations)}")
    print(f"; Functions detected: {len(functions)}")
    print()

    for inst in instructions:
        local_off = inst.offset - seg.file_offset

        # Function label
        if local_off in func_starts:
            f = func_starts[local_off]
            far_str = "FAR " if f.is_far else ""
            frame_str = f" frame={f.local_size}" if f.local_size else ""
            print(f"\n; --- {far_str}function {f.label} (size={f.size}){frame_str} ---")

        # Instruction
        hex_str = ' '.join(f'{b:02X}' for b in inst.raw[:8])

        # Relocation annotation
        reloc_str = ''
        if local_off in reloc_map:
            reloc_str = f'  ; RELOC: {reloc_map[local_off].target_desc}'
        # Also check offsets within the instruction (relocations can point to operand bytes)
        for off in range(local_off + 1, local_off + inst.length):
            if off in reloc_map:
                reloc_str = f'  ; RELOC @+{off - local_off}: {reloc_map[off].target_desc}'

        print(f'{seg.index:3d}:{local_off:04X}  {hex_str:<24s} {inst!r}{reloc_str}')

    print(f"\n; {len(instructions)} instructions, {len(functions)} functions")


def print_summary(ne: NEHeader):
    """Print analysis summary for all code segments."""
    total_funcs = 0
    total_insts = 0
    total_far = 0

    print(f"=== NE Disassembly Summary: {ne.filename} ===")
    print(f"{'Seg':>4s} {'Size':>6s} {'Insts':>6s} {'Funcs':>5s} {'Far':>4s} {'Relocs':>6s} {'IntRef':>6s} {'Import':>6s}")
    print("-" * 52)

    for seg in ne.code_segments:
        instructions, functions, reloc_map = disassemble_segment(seg, ne)
        n_inst = len(instructions)
        n_func = len(functions)
        n_far = sum(1 for f in functions if f.is_far)
        n_int = sum(1 for r in seg.relocations if (r.flags & 3) == 0)
        n_imp = sum(1 for r in seg.relocations if (r.flags & 3) != 0)

        total_funcs += n_func
        total_insts += n_inst
        total_far += n_far

        print(f"{seg.index:4d} {seg.actual_size:6d} {n_inst:6d} {n_func:5d} {n_far:4d} {len(seg.relocations):6d} {n_int:6d} {n_imp:6d}")

    print("-" * 52)
    print(f"{'':>4s} {ne.total_code_size:6d} {total_insts:6d} {total_funcs:5d} {total_far:4d} {ne.total_relocs:6d}")
    print()
    print(f"Total: {total_funcs} functions ({total_far} far), {total_insts} instructions")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ne_exe> [--seg N] [--summary] [--functions]")
        sys.exit(1)

    filepath = sys.argv[1]
    ne = parse_ne(filepath)

    if '--summary' in sys.argv:
        print_summary(ne)
        return

    if '--functions' in sys.argv:
        # List all detected functions
        print(f"=== Functions in {ne.filename} ===")
        for seg in ne.code_segments:
            instructions, functions, _ = disassemble_segment(seg, ne)
            for f in functions:
                far_str = "FAR " if f.is_far else "    "
                print(f"  {far_str}{f.label}  size={f.size:5d}  frame={f.local_size:4d}  insts={f.inst_count}")
        return

    if '--seg' in sys.argv:
        idx = sys.argv.index('--seg')
        seg_num = int(sys.argv[idx + 1])
        seg = next((s for s in ne.segments if s.index == seg_num), None)
        if not seg:
            print(f"Error: segment {seg_num} not found")
            sys.exit(1)
        if not seg.is_code:
            print(f"Error: segment {seg_num} is DATA, not CODE")
            sys.exit(1)
        print_segment_disasm(seg, ne)
    else:
        # Disassemble all code segments
        for seg in ne.code_segments:
            print_segment_disasm(seg, ne)


if __name__ == '__main__':
    main()
