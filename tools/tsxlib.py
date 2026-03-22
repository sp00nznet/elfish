"""
tsxlib.py - TSXLIB Ordinal Mapping for El-Fish Recomp

Maps TSXLIB protected-mode runtime ordinals to C function signatures.
TSXLIB is AnimaTek's proprietary DOS extender providing memory management,
file I/O, FPU emulation, and system services.

Ordinal assignments are inferred from call-site analysis of ELFISH.EXE.
"""

from dataclasses import dataclass


@dataclass
class TSXOrdinal:
    ordinal: int
    name: str
    category: str       # 'fpu', 'mem', 'file', 'sys', 'seg'
    c_signature: str    # C function signature for the recomp runtime
    description: str
    reloc_type: str     # 'OFFSET16' or 'FAR_PTR'
    call_count: int = 0


# TSXLIB ordinal map - inferred from ELFISH.EXE relocation analysis
TSXLIB_ORDINALS = {
    # === FPU Emulation (OFFSET16 relocations, patched inline) ===
    # These patch FWAIT/NOP instructions to call FPU emulation on 386 without 387
    # In recomp: replaced with native FPU operations (double/float)
    22: TSXOrdinal(22, 'tsx_fpu_dispatch', 'fpu',
        'void tsx_fpu_dispatch(CPU *cpu)',
        'FPU instruction dispatch - patches FWAIT before each FPU op',
        'OFFSET16', 17351),
    23: TSXOrdinal(23, 'tsx_fpu_wait', 'fpu',
        'void tsx_fpu_wait(CPU *cpu)',
        'FPU wait/synchronize - patches NOP after FPU store ops',
        'OFFSET16', 2365),
    24: TSXOrdinal(24, 'tsx_fpu_memop', 'fpu',
        'void tsx_fpu_memop(CPU *cpu)',
        'FPU memory operand access - patches FWAIT before FLD/FST with memory',
        'OFFSET16', 1536),

    # === Runtime/Segment Management (OFFSET16 relocations) ===
    3:  TSXOrdinal(3, 'tsx_init_3', 'sys',
        'void tsx_init_3(void)',
        'Runtime initialization (used once)',
        'OFFSET16', 1),
    4:  TSXOrdinal(4, 'tsx_init_4', 'sys',
        'void tsx_init_4(void)',
        'Runtime initialization (used once)',
        'OFFSET16', 1),
    14: TSXOrdinal(14, 'tsx_init_14', 'sys',
        'void tsx_init_14(void)',
        'Runtime initialization (used once)',
        'OFFSET16', 1),
    20: TSXOrdinal(20, 'tsx_seg_load', 'seg',
        'void tsx_seg_load(uint16_t seg_num)',
        'Segment loader - ensure segment is in memory',
        'OFFSET16', 1),
    21: TSXOrdinal(21, 'tsx_seg_unload', 'seg',
        'void tsx_seg_unload(uint16_t seg_num)',
        'Segment unloader - mark segment as discardable',
        'OFFSET16', 1),
    26: TSXOrdinal(26, 'tsx_seg_call', 'seg',
        'void tsx_seg_call(uint16_t seg, uint16_t off)',
        'Far call through segment manager',
        'OFFSET16', 12),
    27: TSXOrdinal(27, 'tsx_seg_jmp', 'seg',
        'void tsx_seg_jmp(uint16_t seg, uint16_t off)',
        'Far jump through segment manager',
        'OFFSET16', 21),
    28: TSXOrdinal(28, 'tsx_seg_ref', 'seg',
        'uint16_t tsx_seg_ref(uint16_t seg)',
        'Get segment selector (pin segment in memory)',
        'OFFSET16', 5),
    30: TSXOrdinal(30, 'tsx_seg_fixup_call', 'seg',
        'void tsx_seg_fixup_call(uint16_t seg, uint16_t off)',
        'Relocated far call fixup',
        'OFFSET16', 12),
    31: TSXOrdinal(31, 'tsx_seg_fixup_jmp', 'seg',
        'void tsx_seg_fixup_jmp(uint16_t seg, uint16_t off)',
        'Relocated far jump fixup',
        'OFFSET16', 21),

    # === System Calls (FAR_PTR relocations, actual function calls) ===
    32: TSXOrdinal(32, 'tsx_dos_call', 'sys',
        'uint16_t tsx_dos_call(uint16_t ax, uint16_t bx, uint16_t cx, uint16_t dx, uint16_t si, uint16_t di)',
        'DOS interrupt dispatch (INT 21h wrapper) - loads all regs from struct',
        'FAR_PTR', 1),
    36: TSXOrdinal(36, 'tsx_file_getinfo', 'file',
        'uint32_t tsx_file_getinfo(uint16_t handle)',
        'Get file handle info (returns seg:off)',
        'FAR_PTR', 2),
    38: TSXOrdinal(38, 'tsx_file_read', 'file',
        'uint16_t tsx_file_read(uint16_t handle, void far *buf, uint16_t count)',
        'Read from file handle',
        'FAR_PTR', 2),
    42: TSXOrdinal(42, 'tsx_file_close', 'file',
        'int tsx_file_close(uint16_t handle)',
        'Close file handle - returns 0 on success',
        'FAR_PTR', 4),
    45: TSXOrdinal(45, 'tsx_int_io', 'sys',
        'uint16_t tsx_int_io(uint8_t func, uint16_t port, uint16_t value)',
        'Port I/O or interrupt function dispatch',
        'FAR_PTR', 3),
    49: TSXOrdinal(49, 'tsx_set_handler', 'sys',
        'void tsx_set_handler(uint8_t int_num)',
        'Set interrupt/exception handler (e.g. INT 24h critical error)',
        'FAR_PTR', 1),
    50: TSXOrdinal(50, 'tsx_save_context', 'sys',
        'void tsx_save_context(void)',
        'Save execution context (for exception/interrupt handling)',
        'FAR_PTR', 2),
    55: TSXOrdinal(55, 'tsx_mem_alloc', 'mem',
        'uint16_t tsx_mem_alloc(uint32_t size)',
        'Allocate memory block - returns selector or handle',
        'FAR_PTR', 2),
    57: TSXOrdinal(57, 'tsx_mem_alloc_small', 'mem',
        'uint16_t tsx_mem_alloc_small(uint16_t size)',
        'Allocate small memory block (< 4KB)',
        'FAR_PTR', 4),
    58: TSXOrdinal(58, 'tsx_mem_free', 'mem',
        'void tsx_mem_free(uint16_t handle)',
        'Free memory block',
        'FAR_PTR', 5),
    62: TSXOrdinal(62, 'tsx_file_open', 'file',
        'uint16_t tsx_file_open(char far *path, uint16_t mode)',
        'Open file - returns handle',
        'FAR_PTR', 3),
    63: TSXOrdinal(63, 'tsx_mem_realloc', 'mem',
        'uint16_t tsx_mem_realloc(uint16_t handle, uint32_t new_size)',
        'Reallocate memory block',
        'FAR_PTR', 2),
    64: TSXOrdinal(64, 'tsx_mem_lock', 'mem',
        'void far *tsx_mem_lock(uint16_t handle)',
        'Lock memory block and return linear address',
        'FAR_PTR', 1),
    65: TSXOrdinal(65, 'tsx_desc_alloc', 'seg',
        'uint16_t tsx_desc_alloc(uint16_t count)',
        'Allocate LDT descriptor(s)',
        'FAR_PTR', 2),
    66: TSXOrdinal(66, 'tsx_desc_get_base', 'seg',
        'uint32_t tsx_desc_get_base(uint16_t selector)',
        'Get descriptor base address',
        'FAR_PTR', 3),
    67: TSXOrdinal(67, 'tsx_huge_alloc', 'mem',
        'uint16_t tsx_huge_alloc(uint32_t size)',
        'Allocate large memory block (>4KB, uses multiple selectors)',
        'FAR_PTR', 2),
    68: TSXOrdinal(68, 'tsx_huge_free', 'mem',
        'void tsx_huge_free(uint16_t handle)',
        'Free large memory block',
        'FAR_PTR', 2),
    72: TSXOrdinal(72, 'tsx_file_create', 'file',
        'uint16_t tsx_file_create(char far *path, uint16_t attr)',
        'Create/open file for writing',
        'FAR_PTR', 1),
    73: TSXOrdinal(73, 'tsx_file_write', 'file',
        'uint16_t tsx_file_write(uint16_t handle, void far *buf, uint16_t count)',
        'Write to file handle',
        'FAR_PTR', 1),
    75: TSXOrdinal(75, 'tsx_file_seek', 'file',
        'uint32_t tsx_file_seek(uint16_t handle, uint32_t offset, uint16_t whence)',
        'Seek file position',
        'FAR_PTR', 1),
}


def get_ordinal(n: int) -> TSXOrdinal:
    """Get TSXLIB ordinal info, or a placeholder if unknown."""
    if n in TSXLIB_ORDINALS:
        return TSXLIB_ORDINALS[n]
    return TSXOrdinal(n, f'tsx_unknown_{n}', 'unknown',
                      f'void tsx_unknown_{n}(void)',
                      f'Unknown TSXLIB ordinal {n}',
                      'UNKNOWN', 0)


def print_ordinal_table():
    """Print the full ordinal mapping table."""
    print("TSXLIB Ordinal Mapping")
    print("=" * 80)
    cats = ['fpu', 'seg', 'sys', 'mem', 'file']
    for cat in cats:
        ords = {k: v for k, v in TSXLIB_ORDINALS.items() if v.category == cat}
        if not ords:
            continue
        print(f"\n--- {cat.upper()} ---")
        for n in sorted(ords.keys()):
            o = ords[n]
            print(f"  {n:3d}: {o.name:<25s} ({o.call_count:6d}x) - {o.description}")


if __name__ == '__main__':
    print_ordinal_table()
