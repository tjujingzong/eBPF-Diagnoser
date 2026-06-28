"""高频/高耗时系统调用探针

检测: 异常频繁或耗时过长的系统调用
tracepoint: raw_syscalls:sys_enter, raw_syscalls:sys_exit
"""

import time
import os
import logging
from src.probes.base import BaseProbe

logger = logging.getLogger(__name__)


SYSCALL_NAMES_X86_64 = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    95: "umask",
    96: "gettimeofday",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    100: "times",
    101: "ptrace",
    102: "getuid",
    104: "getgid",
    105: "geteuid",
    106: "getegid",
    107: "setpgid",
    108: "getppid",
    110: "getpgrp",
    111: "setsid",
    137: "statfs",
    138: "fstatfs",
    157: "prctl",
    158: "arch_prctl",
    174: "rt_sigqueueinfo",
    186: "gettid",
    200: "tkill",
    202: "futex",
    203: "sched_setaffinity",
    204: "sched_getaffinity",
    217: "getdents64",
    218: "set_tid_address",
    228: "clock_gettime",
    229: "clock_getres",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    256: "set_robust_list",
    257: "openat",
    262: "newfstatat",
    270: "preadv",
    271: "pwritev",
    280: "utimensat",
    281: "epoll_pwait",
    288: "accept4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    302: "prlimit64",
    318: "getrandom",
    321: "bpf",
}

SYSCALL_NAMES_ARM64 = {
    17: "getpid",
    29: "ioctl",
    35: "clone",
    49: "chdir",
    56: "openat",
    57: "close",
    62: "lseek",
    63: "read",
    64: "write",
    78: "readlinkat",
    93: "exit",
    94: "exit_group",
    98: "futex",
    101: "nanosleep",
    172: "getpid",
    203: "sched_yield",
    215: "munmap",
    222: "mmap",
    226: "mprotect",
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

    def get_bpf_obj_name(self) -> str:
        return "syscall_probe.bpf.o"

    def attach(self):
        """加载并挂载，然后设置采样率到map"""
        super().attach()
        # 将sample_rate写入sample_rate_map (ARRAY map, index 0)
        try:
            if self._loader and self._obj_index >= 0:
                result = self._loader.send(
                    {
                        "cmd": "WRITE_MAP_ARRAY",
                        "obj_index": self._obj_index,
                        "map": "sample_rate_map",
                        "index": 0,
                        "value": self.sample_rate,
                    }
                )
                if result.get("ok"):
                    logger.debug("syscall sample_rate set to %d", self.sample_rate)
                else:
                    logger.warning("Failed to set sample_rate: %s", result.get("error"))
        except Exception as e:
            logger.warning("Failed to write sample_rate_map: %s", e)

    def poll(self) -> dict:
        now = time.time()
        metrics = {"per_syscall": {}, "global": {}}

        syscall_data = {}
        try:
            for entry in self._read_hash("syscall_stats", max_entries=512):
                nr = entry["key"]
                val = entry["value"]
                syscall_data[nr] = {
                    "call_count": val.get("call_count", 0),
                    "total_time_ns": val.get("total_time_ns", 0),
                    "max_time_ns": val.get("max_time_ns", 0),
                    "err_count": val.get("err_count", 0),
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

                        top_syscalls.append(
                            {
                                "syscall_nr": nr,
                                "name": name,
                                "calls_per_sec": round(calls_per_sec, 1),
                                "avg_time_us": round(avg_time_us, 2),
                                "max_time_ms": round(max_time_ms, 3),
                            }
                        )

                top_syscalls.sort(key=lambda x: x["calls_per_sec"], reverse=True)
                for sc in top_syscalls[:20]:
                    metrics["per_syscall"][sc["name"]] = sc

        self._prev_syscall_stats = syscall_data
        self._prev_timestamp = now

        try:
            total = self._read_array("total_syscalls", 0)
            if isinstance(total, (int, float)):
                metrics["global"]["total_syscalls"] = total
            elif isinstance(total, dict):
                metrics["global"]["total_syscalls"] = total.get("value", 0)
        except (KeyError, TypeError):
            pass

        return metrics
