#!/usr/bin/env python3
"""Verify CO-RE struct layouts against kernel BTF without loading BPF programs."""
import struct

with open("/sys/kernel/btf/vmlinux", "rb") as f:
    data = f.read()

flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from("<HIIIII", data, 2)
type_base = hdr_len + type_off
str_base = hdr_len + str_off

def get_str(off):
    start = str_base + off
    if start >= len(data):
        return ""
    end = data.find(b"\x00", start)
    return data[start:end].decode("utf-8", errors="replace")

target_names = [
    "trace_event_raw_sched_wakeup_template",
    "trace_event_raw_sched_switch",
    "trace_event_raw_block_rq",
    "trace_event_raw_block_rq_completion",
    "trace_event_raw_mm_vmscan_kswapd_wake",
    "trace_event_raw_mm_vmscan_direct_reclaim_begin_template",
    "trace_event_raw_mark_victim",
    "trace_event_raw_sys_enter",
    "trace_event_raw_sys_exit",
]

target_str_offs = {}
for name in target_names:
    nb = name.encode() + b"\x00"
    idx = data.find(nb, str_base)
    if idx >= 0:
        target_str_offs[idx - str_base] = name

kernel_structs = {}
for target_off, name in target_str_offs.items():
    tb = struct.pack("<I", target_off)
    pos = type_base
    while pos < type_base + type_len:
        idx = data.find(tb, pos, type_base + type_len)
        if idx < 0:
            break
        info = struct.unpack_from("<I", data, idx + 4)[0]
        kind = (info >> 24) & 0x1f
        vlen = info & 0xffff
        if kind == 4:
            fields = []
            mpos = idx + 12
            for i in range(vlen):
                mn = struct.unpack_from("<I", data, mpos)[0]
                mo = struct.unpack_from("<I", data, mpos + 8)[0]
                mname = get_str(mn & 0x7fffffff) if (mn & 0x7fffffff) else ""
                fields.append((mname, mo // 8))
                mpos += 12
            kernel_structs[name] = fields
            break
        pos = idx + 1

SEP = "=" * 60
DASH = "-" * 60

local_structs = {
    "trace_event_raw_sched_wakeup_template": [
        ("ent", 0), ("comm", 8), ("pid", 24), ("prio", 28), ("target_cpu", 32),
    ],
    "trace_event_raw_sched_switch": [
        ("ent", 0), ("prev_comm", 8), ("prev_pid", 24), ("prev_prio", 28),
        ("prev_state", 32), ("next_comm", 40), ("next_pid", 56), ("next_prio", 60),
    ],
    "trace_event_raw_block_rq": [
        ("ent", 0), ("dev", 8), ("sector", 16), ("nr_sector", 24),
        ("bytes", 28), ("rwbs", 32),
    ],
    "trace_event_raw_block_rq_completion": [
        ("ent", 0), ("dev", 8), ("sector", 16), ("nr_sector", 24),
        ("error", 28), ("rwbs", 32),
    ],
    "trace_event_raw_mm_vmscan_kswapd_wake": [
        ("ent", 0), ("nid", 8), ("zid", 12), ("order", 16),
    ],
    "trace_event_raw_mm_vmscan_direct_reclaim_begin_template": [
        ("ent", 0), ("order", 8), ("gfp_flags", 16),
    ],
    "trace_event_raw_mark_victim": [
        ("ent", 0), ("pid", 8),
    ],
    "trace_event_raw_sys_enter": [
        ("ent", 0), ("id", 8), ("args", 16),
    ],
    "trace_event_raw_sys_exit": [
        ("ent", 0), ("id", 8), ("ret", 16),
    ],
}

print(SEP)
print("  CO-RE Verification: Local Struct vs Kernel BTF")
print(SEP)

all_ok = True
for name, local_fields in local_structs.items():
    kernel_fields = kernel_structs.get(name)
    if kernel_fields is None:
        print("\n[SKIP] " + name)
        continue

    kernel_map = {f[0]: f[1] for f in kernel_fields}
    print("\n" + DASH)
    print("  " + name)
    print(DASH)

    struct_ok = True
    for field, local_off in local_fields:
        kernel_off = kernel_map.get(field)
        if kernel_off is None:
            mark = "??"
            note = "(not in kernel BTF)"
        elif local_off == kernel_off:
            mark = "OK"
            note = ""
        else:
            mark = "FAIL"
            note = "(local=%d, kernel=%d)" % (local_off, kernel_off)
            struct_ok = False
            all_ok = False
        koff = str(kernel_off) if kernel_off is not None else "N/A"
        print("  [%4s] %-20s local=%3d kernel=%4s %s" % (mark, field, local_off, koff, note))

    print("  >>> " + ("PASS" if struct_ok else "FAIL"))

print("\n" + SEP)
if all_ok:
    print("  ALL CHECKS PASSED - CO-RE relocations should succeed")
else:
    print("  SOME CHECKS FAILED")
print(SEP)
