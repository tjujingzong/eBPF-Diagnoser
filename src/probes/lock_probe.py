"""锁竞争探针

检测: mutex/futex锁热点争用
tracepoint: syscalls:sys_enter_futex, syscalls:sys_exit_futex
"""

import time
from src.probes.base import BaseProbe


class LockProbe(BaseProbe):
    """锁竞争探针"""

    def __init__(self, config):
        super().__init__(config)
        self._prev_futex_stats = {}
        self._prev_timestamp = None

    def get_bpf_obj_name(self) -> str:
        return "lock_probe.bpf.o"

    def poll(self) -> dict:
        now = time.time()
        metrics = {"futex_per_process": {}, "lock_hotspots": [], "global": {}}

        futex_data = {}
        try:
            for entry in self._read_hash("futex_stats", max_entries=256):
                pid = entry["key"]
                val = entry["value"]
                futex_data[pid] = {
                    "call_count": val.get("call_count", 0),
                    "wait_count": val.get("wait_count", 0),
                    "wake_count": val.get("wake_count", 0),
                    "total_wait_ns": val.get("total_wait_ns", 0),
                    "max_wait_ns": val.get("max_wait_ns", 0),
                }
        except Exception:
            pass

        if self._prev_futex_stats and self._prev_timestamp:
            dt = now - self._prev_timestamp
            if dt > 0:
                for pid, curr in futex_data.items():
                    prev = self._prev_futex_stats.get(pid, {})
                    wait_delta = curr["wait_count"] - prev.get("wait_count", 0)
                    latency_delta = curr["total_wait_ns"] - prev.get("total_wait_ns", 0)

                    if wait_delta > 0:
                        avg_wait_ms = (latency_delta / wait_delta) / 1e6
                        max_wait_ms = curr["max_wait_ns"] / 1e6
                        wait_rate = wait_delta / dt
                        comm = self._get_comm(pid)
                        metrics["futex_per_process"][pid] = {
                            "pid": pid, "comm": comm,
                            "futex_wait_per_sec": round(wait_rate, 1),
                            "avg_wait_ms": round(avg_wait_ms, 2),
                            "max_wait_ms": round(max_wait_ms, 2),
                        }

        self._prev_futex_stats = futex_data
        self._prev_timestamp = now

        total_waits = sum(d["wait_count"] for d in futex_data.values())
        total_wait_ns = sum(d["total_wait_ns"] for d in futex_data.values())
        metrics["global"]["total_futex_waits"] = total_waits
        metrics["global"]["total_futex_wait_ms"] = round(total_wait_ns / 1e6, 2)

        # 获取热点堆栈 (top contention stacks)
        try:
            top_stacks = []
            stack_counts = {}
            for entry in self._read_hash("contention_stacks", max_entries=256):
                stack_id = entry["key"]
                count = entry["value"]
                if count > 0:
                    stack_counts[stack_id] = count

            sorted_stacks = sorted(stack_counts.items(), key=lambda x: x[1], reverse=True)[:5]

            all_addrs = []
            stack_addr_map = {}
            for stack_id, count in sorted_stacks:
                addrs = self._read_stack("stack_traces", stack_id)
                if addrs:
                    stack_addr_map[stack_id] = {"count": count, "addrs": addrs}
                    all_addrs.extend(addrs)

            if all_addrs:
                unique_addrs = list(set(all_addrs))
                resolved = self._resolve_ksyms(unique_addrs)
                sym_lookup = dict(zip(unique_addrs, resolved))

                for stack_id, info in stack_addr_map.items():
                    symbols = []
                    for addr in info["addrs"]:
                        sym = sym_lookup.get(addr, "??")
                        if sym:
                            symbols.append(sym)
                    if symbols:
                        top_stacks.append({
                            "count": info["count"],
                            "stack": symbols[:10],
                        })

            metrics["lock_hotspots"] = top_stacks
        except Exception:
            pass

        return metrics

    def _get_comm(self, pid):
        try:
            with open(f"/proc/{pid}/comm") as f:
                return f.read().strip()
        except (FileNotFoundError, ProcessLookupError):
            return f"pid:{pid}"
