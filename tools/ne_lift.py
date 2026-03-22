"""
ne_lift.py - NE-aware 16-bit x86 to C Lifter for El-Fish Recomp

Extends pcrecomp's lift16.py with:
- NE relocation-aware far call resolution
- x87 FPU instruction lifting to native C double operations
- TSXLIB import resolution to C runtime stubs
- Segment-aware memory access

Usage:
    python ne_lift.py <ne_exe> --seg N [--func OFFSET] [--all]
"""

import sys
import os
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'tools', 'tools', 'disasm'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'tools', 'tools', 'lift'))
sys.path.insert(0, os.path.dirname(__file__))

from decode16 import Decoder, Instruction, OpType, Operand, REG16_NAMES
from lift16 import Lifter, _read, _write, _reg16, _sreg, _mem_addr, _label
from ne_parse import parse_ne, NEHeader, Segment
from ne_decode import disassemble_segment, build_reloc_map
from fpu_decode import decode_fpu, format_fpu
from tsxlib import get_ordinal, TSXLIB_ORDINALS


class NELifter(Lifter):
    """Lifts NE executable segments to C code with FPU and relocation support."""

    def __init__(self, ne: NEHeader, seg: Segment):
        super().__init__()
        self.ne = ne
        self.seg = seg
        self.reloc_map = build_reloc_map(seg, ne)
        # Build function name map: (seg_num, offset) -> name
        self.func_names = {}

    def _resolve_far_call(self, inst: Instruction) -> Optional[str]:
        """Resolve a far call instruction using relocation data."""
        local_off = inst.offset - self.seg.file_offset
        # Check relocations at offset+1 (the operand bytes of CALL far)
        for off in range(local_off, local_off + inst.length):
            if off in self.reloc_map:
                ann = self.reloc_map[off]
                r = ann.reloc
                target_type = r.flags & 3
                if target_type == 0:  # Internal
                    if r.target_seg > 0 and r.target_seg != 0xFF:
                        target = self.ne.segments[r.target_seg - 1]
                        if target.is_code:
                            return f'seg{r.target_seg:03d}_{r.target_off:04X}'
                        else:
                            return f'/* data ref seg{r.target_seg}:{r.target_off:04X} */'
                elif target_type == 1:  # Import by ordinal
                    o = get_ordinal(r.ordinal)
                    return o.name
        return None

    def _get_reloc_at(self, local_off: int) -> Optional[object]:
        """Get relocation annotation at a given local offset."""
        return self.reloc_map.get(local_off)

    def lift_instruction(self, inst: Instruction, func_start: int):
        """Override to handle FPU instructions and NE-specific features."""
        m = inst.mnemonic
        op1 = inst.op1
        op2 = inst.op2
        local_off = inst.offset - self.seg.file_offset
        orig = repr(inst)

        # Emit label if this address is a jump target
        self._emit_label(inst.address)

        # --- Skip TSXLIB FPU emulation trampolines ---
        # FWAIT (0x9B) and NOP (0x90) that have TSXLIB.22/23/24 relocations
        # are FPU emulation stubs - skip them in the recomp
        if m in ('wait', 'nop'):
            ann = self._get_reloc_at(local_off)
            if ann and (ann.reloc.flags & 3) == 1:  # Import relocation
                o = get_ordinal(ann.reloc.ordinal)
                if o.category == 'fpu':
                    # Skip FPU emulation trampoline
                    return
            if m == 'wait':
                # Plain FWAIT without relocation - also skip
                return
            if m == 'nop':
                return

        # --- FPU instructions ---
        if m.startswith('f') and not m.startswith('flags'):
            self._lift_fpu(inst, m, orig)
            return

        # --- Far calls with relocation resolution ---
        if m == 'call' and op1 and op1.type == OpType.FAR:
            func_name = self._resolve_far_call(inst)
            if func_name and not func_name.startswith('/*'):
                self._emit(f'push16(cpu, cpu->cs); push16(cpu, 0);', 'far call return addr')
                self._emit(f'{func_name}(cpu);', orig)
            elif func_name:
                self._emit(func_name, orig)
            else:
                self._emit(f'/* unresolved far call {orig} */', orig)
            return

        # --- Near calls ---
        if m == 'call' and op1 and op1.type in (OpType.REL8, OpType.REL16):
            target = op1.disp
            func_name = f'seg{self.seg.index:03d}_{target:04X}'
            self.func_calls.add(func_name)
            self._emit(f'push16(cpu, 0);', 'near call return addr')
            self._emit(f'{func_name}(cpu);', orig)
            return

        # --- Selector loads via relocation ---
        if m == 'mov' and op2 and op2.type in (OpType.IMM8, OpType.IMM16):
            for off in range(local_off + 1, local_off + inst.length):
                ann = self._get_reloc_at(off)
                if ann and ann.reloc.src_type == 2:  # SELECTOR
                    r = ann.reloc
                    if (r.flags & 3) == 0:  # Internal
                        self._emit(_write(op1, f'SEG_{r.target_seg}'),
                                   f'{orig}  /* selector for seg{r.target_seg} */')
                        return

        # --- Default: delegate to base lifter ---
        super().lift_instruction(inst, func_start)

    def _lift_fpu(self, inst: Instruction, m: str, orig: str):
        """Lift an FPU instruction to C double operations."""
        # The FPU mnemonic may include operands (from fpu_decode.py format_fpu)
        # Parse the mnemonic to extract operation and operands
        parts = m.split(' ', 1)
        op = parts[0]
        operand_str = parts[1] if len(parts) > 1 else ''

        # --- FPU Stack Operations ---
        if op == 'fld':
            if 'st(' in operand_str:
                # fld st(i) - push copy of st(i) onto stack
                i = self._parse_st(operand_str)
                self._emit(f'fpu_push(cpu); cpu->st[0] = cpu->st[{i+1}];', orig)
            elif 'dword' in operand_str or 'qword' in operand_str or 'tword' in operand_str:
                mem_expr = self._fpu_mem_read(inst, operand_str)
                self._emit(f'fpu_push(cpu); cpu->st[0] = {mem_expr};', orig)
            else:
                self._emit(f'/* FPU: {orig} */', orig)

        elif op == 'fst':
            if 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'cpu->st[{i}] = cpu->st[0];', orig)
            elif operand_str:
                mem_expr = self._fpu_mem_write(inst, operand_str, 'cpu->st[0]')
                self._emit(mem_expr, orig)
            else:
                self._emit(f'/* FPU: {orig} */', orig)

        elif op == 'fstp':
            if 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'cpu->st[{i}] = cpu->st[0]; fpu_pop(cpu);', orig)
            elif operand_str:
                mem_expr = self._fpu_mem_write(inst, operand_str, 'cpu->st[0]')
                self._emit(f'{mem_expr} fpu_pop(cpu);', orig)
            else:
                self._emit(f'/* FPU: {orig} */', orig)

        elif op == 'fild':
            mem_expr = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'fpu_push(cpu); cpu->st[0] = (double){mem_expr};', orig)

        elif op == 'fist':
            mem_expr = self._fpu_mem_write_int(inst, operand_str, '(int32_t)cpu->st[0]')
            self._emit(mem_expr, orig)

        elif op == 'fistp':
            mem_expr = self._fpu_mem_write_int(inst, operand_str, '(int32_t)cpu->st[0]')
            self._emit(f'{mem_expr} fpu_pop(cpu);', orig)

        # --- FPU Arithmetic ---
        elif op == 'fadd':
            self._lift_fpu_arith(inst, '+', operand_str, orig)
        elif op == 'faddp':
            self._lift_fpu_arith_pop('+', operand_str, orig)
        elif op == 'fsub':
            self._lift_fpu_arith(inst, '-', operand_str, orig)
        elif op == 'fsubp':
            self._lift_fpu_arith_pop('-', operand_str, orig)
        elif op == 'fsubr':
            self._lift_fpu_arith_r(inst, '-', operand_str, orig)
        elif op == 'fsubrp':
            self._lift_fpu_arith_r_pop('-', operand_str, orig)
        elif op == 'fmul':
            self._lift_fpu_arith(inst, '*', operand_str, orig)
        elif op == 'fmulp':
            self._lift_fpu_arith_pop('*', operand_str, orig)
        elif op == 'fdiv':
            self._lift_fpu_arith(inst, '/', operand_str, orig)
        elif op == 'fdivp':
            self._lift_fpu_arith_pop('/', operand_str, orig)
        elif op == 'fdivr':
            self._lift_fpu_arith_r(inst, '/', operand_str, orig)
        elif op == 'fdivrp':
            self._lift_fpu_arith_r_pop('/', operand_str, orig)

        # --- FPU Integer Arithmetic ---
        elif op == 'fiadd':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] += (double){mem};', orig)
        elif op == 'fisub':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] -= (double){mem};', orig)
        elif op == 'fisubr':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] = (double){mem} - cpu->st[0];', orig)
        elif op == 'fimul':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] *= (double){mem};', orig)
        elif op == 'fidiv':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] /= (double){mem};', orig)
        elif op == 'fidivr':
            mem = self._fpu_mem_read_int(inst, operand_str)
            self._emit(f'cpu->st[0] = (double){mem} / cpu->st[0];', orig)

        # --- FPU Compare ---
        elif op == 'fcom':
            if 'st(0), st(' in operand_str:
                i = self._parse_st(operand_str.split('st(0), ')[1])
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[{i}]);', orig)
            elif 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[{i}]);', orig)
            elif operand_str:
                mem = self._fpu_mem_read(inst, operand_str)
                self._emit(f'fpu_compare(cpu, cpu->st[0], {mem});', orig)
            else:
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]);', orig)
        elif op == 'fcomp':
            if 'st(0), st(' in operand_str:
                i = self._parse_st(operand_str.split('st(0), ')[1])
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[{i}]); fpu_pop(cpu);', orig)
            elif 'dword' in operand_str or 'qword' in operand_str:
                mem = self._fpu_mem_read(inst, operand_str)
                self._emit(f'fpu_compare(cpu, cpu->st[0], {mem}); fpu_pop(cpu);', orig)
            else:
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]); fpu_pop(cpu);', orig)
        elif op == 'fcompp':
            self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]); fpu_pop(cpu); fpu_pop(cpu);', orig)
        elif op == 'ftst':
            self._emit(f'fpu_compare(cpu, cpu->st[0], 0.0);', orig)
        elif op == 'fucom':
            if 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[{i}]);', orig)
            else:
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]);', orig)
        elif op == 'fucomp':
            if 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[{i}]); fpu_pop(cpu);', orig)
            else:
                self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]); fpu_pop(cpu);', orig)
        elif op == 'fucompp':
            self._emit(f'fpu_compare(cpu, cpu->st[0], cpu->st[1]); fpu_pop(cpu); fpu_pop(cpu);', orig)

        # --- FPU Constants ---
        elif op == 'fld1':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 1.0;', orig)
        elif op == 'fldz':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 0.0;', orig)
        elif op == 'fldpi':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 3.14159265358979323846;', orig)
        elif op == 'fldl2e':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 1.44269504088896340736;', orig)
        elif op == 'fldl2t':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 3.32192809488736234787;', orig)
        elif op == 'fldlg2':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 0.30102999566398119521;', orig)
        elif op == 'fldln2':
            self._emit(f'fpu_push(cpu); cpu->st[0] = 0.69314718055994530942;', orig)

        # --- FPU Transcendentals ---
        elif op == 'fsqrt':
            self._emit(f'cpu->st[0] = sqrt(cpu->st[0]);', orig)
        elif op == 'fabs':
            self._emit(f'cpu->st[0] = fabs(cpu->st[0]);', orig)
        elif op == 'fchs':
            self._emit(f'cpu->st[0] = -cpu->st[0];', orig)
        elif op == 'fsin':
            self._emit(f'cpu->st[0] = sin(cpu->st[0]);', orig)
        elif op == 'fcos':
            self._emit(f'cpu->st[0] = cos(cpu->st[0]);', orig)
        elif op == 'fpatan':
            self._emit(f'{{ double _y = cpu->st[1], _x = cpu->st[0]; '
                       f'fpu_pop(cpu); cpu->st[0] = atan2(_y, _x); }}', orig)
        elif op == 'fptan':
            self._emit(f'cpu->st[0] = tan(cpu->st[0]); fpu_push(cpu); cpu->st[0] = 1.0;', orig)
        elif op == 'frndint':
            self._emit(f'cpu->st[0] = rint(cpu->st[0]);', orig)
        elif op == 'fscale':
            self._emit(f'cpu->st[0] = ldexp(cpu->st[0], (int)cpu->st[1]);', orig)
        elif op == 'f2xm1':
            self._emit(f'cpu->st[0] = pow(2.0, cpu->st[0]) - 1.0;', orig)
        elif op == 'fyl2x':
            self._emit(f'{{ double _r = cpu->st[1] * log2(cpu->st[0]); '
                       f'fpu_pop(cpu); cpu->st[0] = _r; }}', orig)
        elif op == 'fyl2xp1':
            self._emit(f'{{ double _r = cpu->st[1] * log2(cpu->st[0] + 1.0); '
                       f'fpu_pop(cpu); cpu->st[0] = _r; }}', orig)

        # --- FPU Control ---
        elif op == 'fxch':
            if 'st(' in operand_str:
                i = self._parse_st(operand_str)
                self._emit(f'{{ double _t = cpu->st[0]; cpu->st[0] = cpu->st[{i}]; '
                           f'cpu->st[{i}] = _t; }}', orig)
            else:
                self._emit(f'{{ double _t = cpu->st[0]; cpu->st[0] = cpu->st[1]; '
                           f'cpu->st[1] = _t; }}', orig)
        elif op == 'ffree':
            self._emit(f'/* ffree {operand_str} */', orig)
        elif op == 'finit' or op == 'fninit':
            self._emit(f'fpu_init(cpu);', orig)
        elif op == 'fclex' or op == 'fnclex':
            self._emit(f'cpu->fpu_status &= 0x7F00;', orig)
        elif op == 'fldcw':
            self._emit(f'/* fldcw - load FPU control word */', orig)
        elif op == 'fstcw' or op == 'fnstcw':
            self._emit(f'/* fstcw - store FPU control word */', orig)
        elif op == 'fstsw':
            if 'ax' in operand_str:
                self._emit(f'cpu->ax = cpu->fpu_status;', orig)
            else:
                self._emit(f'/* fstsw {operand_str} */', orig)
        elif op == 'fdecstp':
            self._emit(f'cpu->fpu_top = (cpu->fpu_top - 1) & 7;', orig)
        elif op == 'fincstp':
            self._emit(f'cpu->fpu_top = (cpu->fpu_top + 1) & 7;', orig)
        elif op == 'fnop':
            self._emit(f'/* fnop */', orig)

        # --- Catch-all ---
        else:
            self._emit(f'/* FPU TODO: {orig} */', orig)

    def _lift_fpu_arith(self, inst, op: str, operand_str: str, orig: str):
        """Lift FPU arithmetic: fadd/fsub/fmul/fdiv."""
        if 'st(0), st(' in operand_str:
            i = self._parse_st(operand_str.split('st(0), ')[1])
            self._emit(f'cpu->st[0] = cpu->st[0] {op} cpu->st[{i}];', orig)
        elif 'st(' in operand_str and '), st(0)' in operand_str:
            i = self._parse_st(operand_str)
            self._emit(f'cpu->st[{i}] = cpu->st[{i}] {op} cpu->st[0];', orig)
        elif operand_str:
            mem = self._fpu_mem_read(inst, operand_str)
            self._emit(f'cpu->st[0] = cpu->st[0] {op} {mem};', orig)
        else:
            self._emit(f'cpu->st[0] = cpu->st[0] {op} cpu->st[1];', orig)

    def _lift_fpu_arith_pop(self, op: str, operand_str: str, orig: str):
        """Lift FPU arithmetic with pop: faddp/fsubp/fmulp/fdivp."""
        if 'st(' in operand_str:
            i = self._parse_st(operand_str)
            self._emit(f'cpu->st[{i}] = cpu->st[{i}] {op} cpu->st[0]; fpu_pop(cpu);', orig)
        else:
            self._emit(f'cpu->st[1] = cpu->st[1] {op} cpu->st[0]; fpu_pop(cpu);', orig)

    def _lift_fpu_arith_r(self, inst, op: str, operand_str: str, orig: str):
        """Lift FPU reverse arithmetic: fsubr/fdivr."""
        if 'st(0), st(' in operand_str:
            i = self._parse_st(operand_str.split('st(0), ')[1])
            self._emit(f'cpu->st[0] = cpu->st[{i}] {op} cpu->st[0];', orig)
        elif operand_str:
            mem = self._fpu_mem_read(inst, operand_str)
            self._emit(f'cpu->st[0] = {mem} {op} cpu->st[0];', orig)
        else:
            self._emit(f'cpu->st[0] = cpu->st[1] {op} cpu->st[0];', orig)

    def _lift_fpu_arith_r_pop(self, op: str, operand_str: str, orig: str):
        """Lift FPU reverse arithmetic with pop."""
        if 'st(' in operand_str:
            i = self._parse_st(operand_str)
            self._emit(f'cpu->st[{i}] = cpu->st[0] {op} cpu->st[{i}]; fpu_pop(cpu);', orig)
        else:
            self._emit(f'cpu->st[1] = cpu->st[0] {op} cpu->st[1]; fpu_pop(cpu);', orig)

    def _parse_st(self, operand_str: str) -> int:
        """Extract register number from st(N) pattern, ignoring extra operands."""
        import re
        m = re.search(r'st\((\d+)\)', operand_str)
        return int(m.group(1)) if m else 0

    def _fpu_mem_expr(self, inst, operand_str: str) -> tuple:
        """Get (seg_expr, off_expr) for FPU memory operand.
        Uses inst.op1 if available (preserved from ModR/M decode), otherwise falls back."""
        if inst and inst.op1 and inst.op1.type in (OpType.MEM, OpType.MOFFS):
            seg, off = _mem_addr(inst.op1)
            return seg, off
        # Fallback: can't resolve, emit a comment
        return 'cpu->ds', f'0 /* TODO: {operand_str} */'

    def _fpu_mem_read(self, inst, operand_str: str) -> str:
        """Generate C expression to read FPU memory operand as double."""
        seg, off = self._fpu_mem_expr(inst, operand_str)
        if 'qword' in operand_str:
            return f'fpu_read_f64(cpu, {seg}, {off})'
        elif 'tword' in operand_str:
            return f'fpu_read_f64(cpu, {seg}, {off}) /* tword approx */'
        else:  # dword
            return f'fpu_read_f32(cpu, {seg}, {off})'

    def _fpu_mem_write(self, inst, operand_str: str, value: str) -> str:
        """Generate C statement to write FPU value to memory."""
        seg, off = self._fpu_mem_expr(inst, operand_str)
        if 'qword' in operand_str:
            return f'fpu_write_f64(cpu, {seg}, {off}, {value});'
        elif 'tword' in operand_str:
            return f'fpu_write_f64(cpu, {seg}, {off}, {value}); /* tword approx */'
        else:  # dword
            return f'fpu_write_f32(cpu, {seg}, {off}, {value});'

    def _fpu_mem_read_int(self, inst, operand_str: str) -> str:
        """Generate C expression to read FPU integer memory operand."""
        seg, off = self._fpu_mem_expr(inst, operand_str)
        if 'dword' in operand_str:
            return f'fpu_read_i32(cpu, {seg}, {off})'
        else:  # word
            return f'fpu_read_i16(cpu, {seg}, {off})'

    def _fpu_mem_write_int(self, inst, operand_str: str, value: str) -> str:
        """Generate C statement to write integer to FPU memory."""
        seg, off = self._fpu_mem_expr(inst, operand_str)
        if 'dword' in operand_str:
            return f'fpu_write_i32(cpu, {seg}, {off}, {value});'
        else:  # word
            return f'fpu_write_i16(cpu, {seg}, {off}, {value});'


def lift_segment(ne: NEHeader, seg_num: int, func_offset: int = -1):
    """Lift functions from a segment to C code."""
    seg = next((s for s in ne.segments if s.index == seg_num), None)
    if not seg or not seg.is_code:
        print(f"Error: segment {seg_num} not found or not CODE")
        return

    instructions, functions, reloc_map = disassemble_segment(seg, ne)

    if not functions:
        print(f"/* No functions detected in segment {seg_num} */")
        return

    # Header
    print(f'/* Segment {seg_num} - {seg.actual_size} bytes, {len(functions)} functions */')
    print(f'/* Auto-generated by ne_lift.py - El-Fish Recomp */')
    print()
    print('#include "segments.h"')
    print()

    # Lift each function
    lifter = NELifter(ne, seg)

    target_funcs = functions
    if func_offset >= 0:
        target_funcs = [f for f in functions if f.offset == func_offset]
        if not target_funcs:
            print(f"/* Function at offset 0x{func_offset:04X} not found */")
            return

    for func in target_funcs:
        # Get instructions for this function
        func_insts = [i for i in instructions
                      if func.offset <= (i.offset - seg.file_offset) < func.end]
        if not func_insts:
            continue

        code = lifter.lift_function(
            func.label, func_insts, seg.file_offset + func.offset, func.is_far)
        print(code)
        print()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ne_exe> --seg N [--func OFFSET]")
        sys.exit(1)

    filepath = sys.argv[1]
    ne = parse_ne(filepath)

    if '--seg' not in sys.argv:
        print("Error: --seg N required")
        sys.exit(1)

    idx = sys.argv.index('--seg')
    seg_num = int(sys.argv[idx + 1])

    func_offset = -1
    if '--func' in sys.argv:
        idx = sys.argv.index('--func')
        func_offset = int(sys.argv[idx + 1], 0)

    lift_segment(ne, seg_num, func_offset)


if __name__ == '__main__':
    main()
