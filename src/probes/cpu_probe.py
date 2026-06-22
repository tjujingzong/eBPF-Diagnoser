"""CPU异常探针

检测: CPU异常占用、调度延迟、busy loop、线程竞争
tracepoint: sched:sched_switch
"""

import os
import time
from collections import defaultdict
from src.probes.base import BaseProbe


# BPF C程序: CPU探针 (兼容Kernel 6.6+)
CPU_BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 每进程CPU统计
struct cpu_proc_stat {
    u32 pid;
    u64 switch_count;
    char comm[TASK_COMM_LEN];
};

// 全局统计
struct global_stat {
    u64 total_switches;
    u64 sample_count;
};

BPF_HASH(proc_stats, u32, struct cpu_proc_stat);
BPF_ARRAY(global, struct global_stat, 1);

// sched_switch: 上下文切换
TRACEPOINT_PROBE(sched, sched_switch) {
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;

    // 简单采样: 每__SAMPLE_RATE__次采集一次
    u32 zero_idx = 0;
    struct global_stat *g = global.lookup(&zero_idx);
    if (!g) {
        struct global_stat new_g = {};
        new_g.total_switches = 1;
        new_g.sample_count = 1;
        global.update(&zero_idx, &new_g);
    } else {
        g->total_switches += 1;
        g->sample_count += 1;
    }

    // 更新prev进程
    struct cpu_proc_stat *prev_stat = proc_stats.lookup(&prev_pid);
    if (prev_stat) {
        prev_stat->switch_count += 1;
    } else {
        struct cpu_proc_stat new_stat = {};
        new_stat.pid = prev_pid;
        new_stat.switch_count = 1;
        bpf_get_current_comm(&new_stat.comm, sizeof(new_stat.comm));
        proc_stats.update(&prev_pid, &new_stat);
    }

    return 0;
}
"""


class CpuProbe(BaseProbe):
    """CPU异常探针"""

    def __init__(self, config):
        super().__init__(config)
        self._prev_cpu_stat = None
        self._prev_timestamp = None
        self._proc_cpu_prev = {}  # pid -> (utime_ticks, stime_ticks)

    def get_bpf_text(self) -> str:
        return CPU_BPF_TEXT.replace("__SAMPLE_RATE__", str(self.sample_rate))

    def _attach_tracepoints(self):
        """sched tracepoint由BCC自动挂载"""
        pass

    def poll(self) -> dict:
        """轮询CPU指标"""
        now = time.time()
        metrics = {
            "per_process": {},
            "global": {},
        }

        # 1. 从/proc/stat获取系统级CPU统计
        proc_stat = self._read_proc_stat()
        if proc_stat:
            cpu_stat = self._calc_cpu_usage(proc_stat)
            metrics["global"].update(cpu_stat)

        # 2. 从/proc/stat获取运行队列长度和上下文切换
        try:
            with open("/proc/stat") as f:
                for line in f:
                    if line.startswith("procs_running"):
                        metrics["global"]["runqueue_length"] = int(line.split()[1])
                    elif line.startswith("ctxt"):
                        metrics["global"]["context_switches_total"] = int(line.split()[1])
        except (FileNotFoundError, ValueError):
            pass

        # 3. 计算每进程CPU使用率(通过/proc/<pid>/stat)
        if self._prev_timestamp and (now - self._prev_timestamp) > 0:
            dt = now - self._prev_timestamp
            procs = []
            try:
                for pid_dir in os.listdir("/proc"):
                    if not pid_dir.isdigit():
                        continue
                    try:
                        with open(f"/proc/{pid_dir}/stat") as f:
                            fields = f.read().split()
                        utime = int(fields[13])
                        stime = int(fields[14])
                        comm = fields[1].strip("()")
                        total_ticks = utime + stime

                        prev = self._proc_cpu_prev.get(int(pid_dir))
                        if prev:
                            cpu_pct = (total_ticks - prev) / os.sysconf("SC_CLK_TCK") / dt * 100.0
                        else:
                            cpu_pct = 0.0
                        self._proc_cpu_prev[int(pid_dir)] = total_ticks

                        if cpu_pct > 0.5:
                            procs.append({
                                "pid": int(pid_dir),
                                "comm": comm,
                                "cpu_percent": round(cpu_pct, 1),
                            })
                    except (FileNotFoundError, ValueError, ProcessLookupError, IndexError):
                        continue
            except FileNotFoundError:
                pass

            procs.sort(key=lambda x: x["cpu_percent"], reverse=True)
            for p in procs[:20]:
                metrics["per_process"][p["pid"]] = p

        # 4. 从BPF MAP获取上下文切换统计
        try:
            zero_idx = 0
            g = self.bpf["global"][zero_idx]
            total_sw = g.total_switches
            if self._prev_timestamp:
                dt = now - self._prev_timestamp
                if dt > 0 and total_sw > 0:
                    metrics["global"]["context_switches_per_sec"] = round(total_sw / dt, 0)
        except (IndexError, KeyError):
            pass

        # 5. 从BPF MAP获取每进程切换统计
        try:
            for key, val in self.bpf["proc_stats"].items():
                pid = key.value
                if pid not in metrics["per_process"]:
                    try:
                        with open(f"/proc/{pid}/comm") as f:
                            comm = f.read().strip()
                        metrics["per_process"][pid] = {
                            "pid": pid,
                            "comm": comm,
                            "switch_count": val.switch_count,
                        }
                    except (FileNotFoundError, ProcessLookupError):
                        pass
        except Exception:
            pass

        self._prev_timestamp = now
        self._prev_cpu_stat = proc_stat
        return metrics

    def _calc_cpu_usage(self, proc_stat: dict) -> dict:
        """计算系统级CPU使用率"""
        result = {}
        if self._prev_cpu_stat:
            dt_idle = proc_stat.get("idle", 0) - self._prev_cpu_stat.get("idle", 0)
            dt_iowait = proc_stat.get("iowait", 0) - self._prev_cpu_stat.get("iowait", 0)
            dt_total = proc_stat.get("total", 1) - self._prev_cpu_stat.get("total", 1)

            if dt_total > 0:
                result["cpu_usage_percent"] = round((1 - dt_idle / dt_total) * 100, 1)
                result["cpu_iowait_percent"] = round(dt_iowait / dt_total * 100, 1)
                result["cpu_user_percent"] = round(
                    (proc_stat.get("user", 0) - self._prev_cpu_stat.get("user", 0)) / dt_total * 100, 1
                )
                result["cpu_system_percent"] = round(
                    (proc_stat.get("system", 0) - self._prev_cpu_stat.get("system", 0)) / dt_total * 100, 1
                )
        return result