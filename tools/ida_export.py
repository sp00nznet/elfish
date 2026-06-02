"""
ida_export.py - Export accurate code structure from IDA for the lifter.

For each NE CODE segment (NE number = IDA segment index + 1), dumps:
  - functions: sorted list of function entry offsets (segment-relative)
  - heads:     sorted list of every code instruction head offset
  - code_ranges: merged [start,end) ranges IDA classified as code (data excluded)

Run: py -3.11 tools/ida_export.py <binary> <out.json>
"""
import sys
import json
import idapro
import ida_auto, ida_segment, ida_funcs, ida_bytes, idautils

binary = sys.argv[1]
out_path = sys.argv[2]

if idapro.open_database(binary, run_auto_analysis=True):
    raise SystemExit("open failed")
ida_auto.auto_wait()

result = {}
try:
    n = ida_segment.get_segm_qty()
    for i in range(n):
        s = ida_segment.getnseg(i)
        cls = ida_segment.get_segm_class(s) or ""
        if cls != "CODE":
            continue
        ne = i + 1
        base = s.start_ea
        funcs = sorted(int(ea - base) for ea in idautils.Functions(s.start_ea, s.end_ea))
        heads = []
        ranges = []
        cur_start = None
        prev_end = None
        ea = s.start_ea
        while ea < s.end_ea:
            flags = ida_bytes.get_flags(ea)
            sz = ida_bytes.get_item_size(ea)
            if sz <= 0:
                sz = 1
            if ida_bytes.is_code(flags):
                heads.append(int(ea - base))
                if cur_start is None:
                    cur_start = ea
                prev_end = ea + sz
            else:
                if cur_start is not None:
                    ranges.append([int(cur_start - base), int(prev_end - base)])
                    cur_start = None
            ea += sz
        if cur_start is not None:
            ranges.append([int(cur_start - base), int(prev_end - base)])
        result[str(ne)] = {"functions": funcs, "heads": heads, "code_ranges": ranges}
finally:
    idapro.close_database(save=False)

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)

tot_f = sum(len(v["functions"]) for v in result.values())
tot_h = sum(len(v["heads"]) for v in result.values())
print(f"Wrote {out_path}: {len(result)} code segments, {tot_f} functions, {tot_h} code heads")
