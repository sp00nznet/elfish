"""Probe: dump IDA's segment layout for the NE so we can map IDA segments
to NE segment numbers. Run: py -3.11 tools/ida_probe_segs.py <binary>"""
import sys
import idapro
import ida_auto, ida_segment, idautils, ida_funcs, idc

binary = sys.argv[1]
if idapro.open_database(binary, run_auto_analysis=True):
    raise SystemExit("open failed")
ida_auto.auto_wait()

try:
    print("=== SEGMENTS ===")
    n = ida_segment.get_segm_qty()
    for i in range(n):
        s = ida_segment.getnseg(i)
        name = ida_segment.get_segm_name(s) or "?"
        cls = ida_segment.get_segm_class(s) or "?"
        size = s.end_ea - s.start_ea
        fcount = sum(1 for _ in idautils.Functions(s.start_ea, s.end_ea))
        if cls != "CODE" and i < 110:
            continue  # skip the data segments in this listing
        print(f"idx={i:3d} NE={i+1:3d} name={name:12s} class={cls:6s} "
              f"start={s.start_ea:08X} end={s.end_ea:08X} sel={s.sel:5d} "
              f"bitness={s.bitness} size={size:6d} funcs={fcount}")
    print(f"total segments: {n}")
    print(f"total functions: {len(list(idautils.Functions()))}")
finally:
    idapro.close_database(save=False)
