"""内存抖动/OOM探针

检测: 内存异常、频繁缺页、回收压力、OOM风险
tracepoint: vmscan, oom
额外: /proc/meminfo, /proc/vmstat
"""

import time
import os
from src.probes.base import BaseProbe


MEM_BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>

// 系统级内存事件
struct mem_event_stats {
    u64 kswapd_wake_count;
    u64 direct_reclaim_count;
    u64 oom_kill_count;
};

BPF_ARRAY(mem_stats, struct mem_event_stats, 1);

// kswapd唤醒
TRACEPOINT_PROBE(vmscan, mm_vmscan_kswapd_wake) {
    u32 zero = 0;
    struct mem_event_stats *stat = mem_stats.lookup(&zero);
    if (stat) {
        stat->kswapd_wake_count += 1;
    } else {
        struct mem_event_stats new_stat = {};
        new_stat.kswapd_wake_count = 1;
        mem_stats.update(&zero, &new_stat);
    }
    return 0;
}

// 直接回收
TRACEPOINT_PROBE(vmscan, mm_vmscan_direct_reclaim_begin) {
    u32 zero = 0;
    struct mem_event_stats *stat = mem_stats.lookup(&zero);
    if (stat) {
        stat->direct_reclaim_count += 1;
    } else {
        struct mem_event_stats new_stat = {};
        new_stat.direct_reclaim_count = 1;
        mem_stats.update(&zero, &new_stat);
    }
    return 0;
}

// OOM kill
TRACEPOINT_PROBE(oom, mark_victim) {
    u32 zero = 0;
    struct mem_event_stats *stat = mem_stats.lookup(&zero);
    if (stat) {
        stat->oom_kill_count += 1;
    } else {
        struct mem_event_stats new_stat = {};
        new_stat.oom_kill_count = 1;
        mem_stats.update(&zero, &new_stat);
    }
    return 0;
}
"""


class MemProbe(BaseProbe):
    """内存抖动/OOM探针"""

    def __init__(self, config):
        super().__init__(config)
        self._prev_vmstat = {}
        self._prev_timestamp = None
        self._prev_mem_events = None

    def get_bpf_text(self) -> str:
        return MEM_BPF_TEXT.replace("__SAMPLE_RATE__", str(self.sample_rate))

    def _attach_tracepoints(self):
        """vmscan/oom tracepoint由BCC自动挂载"""
        pass

    def poll(self) -> dict:
        """轮询内存指标"""
        now = time.time()
        metrics = {"system": {}, "events": {}, "per_process": []}

        # 1. /proc/meminfo
        meminfo = self._read_proc_meminfo()
        if meminfo:
            total_kb = meminfo.get("MemTotal", 0)
            available_kb = meminfo.get("MemAvailable", 0)
            if total_kb > 0:
                metrics["system"]["total_mb"] = round(total_kb / 1024, 1)
                metrics["system"]["available_mb"] = round(available_kb / 1024, 1)
                metrics["system"]["available_percent"] = round(available_kb / total_kb * 100, 1)
                metrics["system"]["used_percent"] = round((1 - available_kb / total_kb) * 100, 1)
                metrics["system"]["anon_mb"] = round(meminfo.get("AnonPages", 0) / 1024, 1)
                swap_total = meminfo.get("SwapTotal", 0)
                if swap_total > 0:
                    swap_free = meminfo.get("SwapFree", 0)
                    metrics["system"]["swap_used_mb"] = round((swap_total - swap_free) / 1024, 1)
                    metrics["system"]["swap_used_percent"] = round((swap_total - swap_free) / swap_total * 100, 1)

        # 2. /proc/vmstat
        vmstat = self._read_vmstat()
        if vmstat and self._prev_vmstat:
            dt = now - self._prev_timestamp if self._prev_timestamp else 1
            if dt > 0:
                metrics["system"]["pgfault_per_sec"] = self._delta_rate(vmstat, self._prev_vmstat, "pgfault", dt)
                metrics["system"]["pgmajfault_per_sec"] = self._delta_rate(vmstat, self._prev_vmstat, "pgmajfault", dt)
                metrics["system"]["pswpin_per_sec"] = self._delta_rate(vmstat, self._prev_vmstat, "pswpin", dt)
                metrics["system"]["pswpout_per_sec"] = self._delta_rate(vmstat, self._prev_vmstat, "pswpout", dt)

        self._prev_vmstat = vmstat

        # 3. BPF事件统计
        try:
            stat = self.bpf["mem_stats"][0]
            curr_events = {
                "direct_reclaim_count": stat.direct_reclaim_count,
                "kswapd_wake_count": stat.kswapd_wake_count,
                "oom_kill_count": stat.oom_kill_count,
            }
            if self._prev_mem_events and self._prev_timestamp:
                dt = now - self._prev_timestamp
                if dt > 0:
                    metrics["events"]["direct_reclaim_per_sec"] = round(
                        (curr_events["direct_reclaim_count"] - self._prev_mem_events.get("direct_reclaim_count", 0)) / dt, 2
                    )
                    metrics["events"]["kswapd_wake_per_sec"] = round(
                        (curr_events["kswapd_wake_count"] - self._prev_mem_events.get("kswapd_wake_count", 0)) / dt, 2
                    )

            metrics["events"]["direct_reclaim_total"] = curr_events["direct_reclaim_count"]
            metrics["events"]["kswapd_wake_total"] = curr_events["kswapd_wake_count"]
            metrics["events"]["oom_kill_total"] = curr_events["oom_kill_count"]
            self._prev_mem_events = curr_events
        except (IndexError, KeyError):
            pass

        # 4. Top内存进程
        metrics["per_process"] = self._get_top_mem_processes(10)
        self._prev_timestamp = now
        return metrics

    def _read_vmstat(self) -> dict:
        vmstat = {}
        try:
            with open("/proc/vmstat") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) == 2:
                        try:
                            vmstat[parts[0]] = int(parts[1])
                        except ValueError:
                            pass
        except FileNotFoundError:
            pass
        return vmstat

    def _delta_rate(self, curr, prev, key, dt):
        if dt <= 0:
            return 0.0
        return round((curr.get(key, 0) - prev.get(key, 0)) / dt, 2)

    def _get_top_mem_processes(self, n=10):
        procs = []
        try:
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid_dir}/statm") as f:
                        fields = f.read().split()
                        if len(fields) >= 2:
                            rss_pages = int(fields[1])
                            rss_mb = rss_pages * 4 / 1024
                    with open(f"/proc/{pid_dir}/comm") as f:
                        comm = f.read().strip()
                    if rss_mb > 1:
                        procs.append({"pid": int(pid_dir), "comm": comm, "rss_mb": round(rss_mb, 1)})
                except (FileNotFoundError, ProcessLookupError, ValueError):
                    continue
        except FileNotFoundError:
            pass
        procs.sort(key=lambda x: x["rss_mb"], reverse=True)
        return procs[:n]