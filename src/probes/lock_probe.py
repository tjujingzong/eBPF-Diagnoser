"""锁竞争探针

检测: mutex/futex锁热点争用
tracepoint: syscalls:sys_enter_futex, syscalls:sys_exit_futex
"""

import time
import os
from src.probes.base import BaseProbe


LOCK_BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 每进程futex统计
struct futex_stat {
    u64 call_count;
    u64 wait_count;
    u64 wake_count;
    u64 total_wait_ns;
    u64 max_wait_ns;
};

BPF_HASH(futex_stats, u32, struct futex_stat);
BPF_HASH(futex_start, u64, u64);  // tid -> start_ts

// futex_enter
TRACEPOINT_PROBE(syscalls, sys_enter_futex) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 tid = bpf_get_current_pid_tgid();
    u32 op = args->op & 0xF;

    struct futex_stat *stat = futex_stats.lookup(&pid);
    if (!stat) {
        struct futex_stat new_stat = {};
        futex_stats.update(&pid, &new_stat);
        stat = futex_stats.lookup(&pid);
    }
    if (stat) {
        stat->call_count += 1;
        if (op == 0) {  // FUTEX_WAIT
            stat->wait_count += 1;
            u64 ts = bpf_ktime_get_ns();
            futex_start.update(&tid, &ts);
        } else if (op == 1) {  // FUTEX_WAKE
            stat->wake_count += 1;
        }
    }
    return 0;
}

// futex_exit
TRACEPOINT_PROBE(syscalls, sys_exit_futex) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 *start_ts = futex_start.lookup(&tid);
    if (!start_ts) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 latency_ns = ts - *start_ts;
    futex_start.delete(&tid);

    u32 pid = tid >> 32;
    struct futex_stat *stat = futex_stats.lookup(&pid);
    if (stat) {
        stat->total_wait_ns += latency_ns;
        if (latency_ns > stat->max_wait_ns) {
            stat->max_wait_ns = latency_ns;
        }
    }
    return 0;
}
"""


class LockProbe(BaseProbe):
    """锁竞争探针"""

    def __init__(self, config):
        super().__init__(config)
        self._prev_futex_stats = {}
        self._prev_timestamp = None

    def get_bpf_text(self) -> str:
        return LOCK_BPF_TEXT.replace("__SAMPLE_RATE__", str(self.sample_rate))

    def _attach_tracepoints(self):
        pass

    def poll(self) -> dict:
        now = time.time()
        metrics = {"futex_per_process": {}, "lock_hotspots": [], "global": {}}

        futex_data = {}
        try:
            for key, val in self.bpf["futex_stats"].items():
                pid = key.value
                futex_data[pid] = {
                    "call_count": val.call_count,
                    "wait_count": val.wait_count,
                    "wake_count": val.wake_count,
                    "total_wait_ns": val.total_wait_ns,
                    "max_wait_ns": val.max_wait_ns,
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
        return metrics

    def _get_comm(self, pid):
        try:
            with open(f"/proc/{pid}/comm") as f:
                return f.read().strip()
        except (FileNotFoundError, ProcessLookupError):
            return f"pid:{pid}"