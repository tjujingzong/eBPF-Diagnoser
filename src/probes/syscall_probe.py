"""高频/高耗时系统调用探针

检测: 异常频繁或耗时过长的系统调用
tracepoint: raw_syscalls:sys_enter, raw_syscalls:sys_exit
"""

import time
import os
from collections import defaultdict
from src.probes.base import BaseProbe


# 注意: raw_syscalls极高频(每秒数万次)，必须用采样
SYSCALL_BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 每syscall统计
struct syscall_stat {
    u64 call_count;
    u64 total_time_ns;
    u64 max_time_ns;
    u64 err_count;
};

BPF_HASH(syscall_stats, u32, struct syscall_stat);
BPF_HASH(syscall_start, u64, u64);  // tid -> start_ts
BPF_ARRAY(total_syscalls, u64, 1);

// 采样计数器
BPF_ARRAY(sample_ctr, u64, 1);

// sys_enter
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    // 采样控制
    u32 zero = 0;
    u64 *ctr = sample_ctr.lookup(&zero);
    if (ctr) {
        u64 c = *ctr;
        if (c % __SAMPLE_RATE__ != 0) {
            *ctr = c + 1;
            return 0;
        }
        *ctr = c + 1;
    } else {
        u64 one = 1;
        sample_ctr.update(&zero, &one);
    }

    u64 tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    syscall_start.update(&tid, &ts);

    // 总计数
    u64 *total = total_syscalls.lookup(&zero);
    if (total) {
        (*total) += 1;
    }
    return 0;
}

// sys_exit
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 *start_ts = syscall_start.lookup(&tid);
    if (!start_ts) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    u64 duration_ns = ts - *start_ts;
    syscall_start.delete(&tid);

    u32 syscall_nr = args->id;
    long ret = args->ret;

    struct syscall_stat *stat = syscall_stats.lookup(&syscall_nr);
    if (stat) {
        stat->call_count += 1;
        stat->total_time_ns += duration_ns;
        if (duration_ns > stat->max_time_ns) {
            stat->max_time_ns = duration_ns;
        }
        if (ret < 0) {
            stat->err_count += 1;
        }
    } else {
        struct syscall_stat new_stat = {};
        new_stat.call_count = 1;
        new_stat.total_time_ns = duration_ns;
        new_stat.max_time_ns = duration_ns;
        new_stat.err_count = (ret < 0) ? 1 : 0;
        syscall_stats.update(&syscall_nr, &new_stat);
    }
    return 0;
}
"""


# Linux系统调用号映射
SYSCALL_NAMES_X86_64 = {
    0: "read", 1: "write", 2: "open", 3: "close", 9: "mmap",
    10: "mprotect", 11: "munmap", 13: "rt_sigaction", 16: "ioctl",
    35: "nanosleep", 39: "getpid", 56: "clone", 57: "fork", 59: "execve",
    60: "exit", 202: "futex", 231: "epoll_wait", 257: "openat",
}

SYSCALL_NAMES_ARM64 = {
    17: "getpid", 29: "ioctl", 35: "clone", 49: "chdir",
    56: "openat", 57: "close", 62: "lseek", 63: "read", 64: "write",
    78: "readlinkat", 93: "exit", 94: "exit_group", 98: "futex",
    101: "nanosleep", 172: "getpid", 203: "sched_yield", 215: "munmap",
    222: "mmap", 226: "mprotect",
}


class SyscallProbe(BaseProbe):
    """高频/高耗时系统调用探针"""

    def __init__(self, config):
        super().__init__(config)
        self._prev_syscall_stats = {}
        self._prev_timestamp = None
        self._syscall_names = self._detect_syscall_names()

    def _detect_syscall_names(self):
        arch = os.uname().machine
        if "x86_64" in arch:
            return SYSCALL_NAMES_X86_64
        elif "aarch64" in arch or "arm64" in arch:
            return SYSCALL_NAMES_ARM64
        return self._parse_syscall_names()

    def _parse_syscall_names(self):
        names = {}
        for path in [
            "/usr/include/asm/unistd_64.h",
            "/usr/include/asm-generic/unistd.h",
        ]:
            try:
                with open(path) as f:
                    for line in f:
                        if "#define __NR_" in line:
                            parts = line.split()
                            if len(parts) == 3:
                                name = parts[1].replace("__NR_", "")
                                try:
                                    names[int(parts[2])] = name
                                except ValueError:
                                    pass
                if names:
                    break
            except FileNotFoundError:
                continue
        return names

    def get_bpf_text(self) -> str:
        return SYSCALL_BPF_TEXT.replace("__SAMPLE_RATE__", str(self.sample_rate))

    def _attach_tracepoints(self):
        pass

    def poll(self) -> dict:
        now = time.time()
        metrics = {"per_syscall": {}, "global": {}}

        syscall_data = {}
        try:
            for key, val in self.bpf["syscall_stats"].items():
                nr = key.value
                syscall_data[nr] = {
                    "call_count": val.call_count,
                    "total_time_ns": val.total_time_ns,
                    "max_time_ns": val.max_time_ns,
                    "err_count": val.err_count,
                }
        except Exception:
            pass

        if self._prev_syscall_stats and self._prev_timestamp:
            dt = now - self._prev_timestamp
            if dt > 0:
                top_syscalls = []
                for nr, curr in syscall_data.items():
                    prev = self._prev_syscall_stats.get(nr, {})
                    call_delta = curr["call_count"] - prev.get("call_count", 0)
                    time_delta = curr["total_time_ns"] - prev.get("total_time_ns", 0)

                    if call_delta > 0:
                        name = self._syscall_names.get(nr, f"sys_{nr}")
                        calls_per_sec = call_delta / dt
                        avg_time_us = (time_delta / call_delta) / 1000
                        max_time_ms = curr["max_time_ns"] / 1e6

                        top_syscalls.append({
                            "syscall_nr": nr, "name": name,
                            "calls_per_sec": round(calls_per_sec, 1),
                            "avg_time_us": round(avg_time_us, 2),
                            "max_time_ms": round(max_time_ms, 3),
                        })

                top_syscalls.sort(key=lambda x: x["calls_per_sec"], reverse=True)
                for sc in top_syscalls[:20]:
                    metrics["per_syscall"][sc["name"]] = sc

        self._prev_syscall_stats = syscall_data
        self._prev_timestamp = now

        try:
            total = self.bpf["total_syscalls"][0].value
            metrics["global"]["total_syscalls"] = total
        except (IndexError, KeyError):
            pass

        return metrics