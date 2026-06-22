"""探针基类

所有eBPF探针的抽象基类，定义统一接口
"""

import os
import time
import resource
from abc import ABC, abstractmethod
from typing import Optional


class BaseProbe(ABC):
    """eBPF探针基类"""

    def __init__(self, config):
        self.config = config
        self.bpf = None
        self.sample_rate = 1
        self._start_time = None
        self._start_cpu_time = None
        self._attached = False

    @abstractmethod
    def get_bpf_text(self) -> str:
        """返回BPF C代码文本"""
        pass

    @abstractmethod
    def poll(self) -> dict:
        """轮询并返回当前指标快照

        Returns:
            dict: 指标字典，键为指标名，值为数值或嵌套dict
        """
        pass

    def attach(self):
        """加载BPF程序并挂载到tracepoint"""
        from bcc import BPF

        bpf_text = self.get_bpf_text()
        # 注入采样率
        bpf_text = bpf_text.replace("__SAMPLE_RATE__", str(self.sample_rate))

        self.bpf = BPF(text=bpf_text)
        self._attach_tracepoints()
        self._start_time = time.time()
        self._start_cpu_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        self._attached = True

    @abstractmethod
    def _attach_tracepoints(self):
        """挂载具体的tracepoint，子类实现"""
        pass

    def detach(self):
        """卸载BPF程序"""
        if self.bpf:
            self.bpf.cleanup()
            self.bpf = None
        self._attached = False

    def set_sample_rate(self, rate: int):
        """设置采样率 (1=全采样, N=1/N采样)"""
        self.sample_rate = max(1, rate)

    def get_overhead(self) -> dict:
        """获取探针自身的CPU和内存开销"""
        if not self._attached:
            return {"cpu_percent": 0, "memory_mb": 0}

        current_cpu = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        elapsed = time.time() - self._start_time if self._start_time else 1
        cpu_percent = (current_cpu - self._start_cpu_time) / elapsed * 100 if elapsed > 0 else 0

        # 获取RSS内存
        with open(f"/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    memory_mb = int(line.split()[1]) / 1024
                    break
            else:
                memory_mb = 0

        return {
            "cpu_percent": round(cpu_percent, 2),
            "memory_mb": round(memory_mb, 2),
        }

    def _read_proc_stat(self) -> dict:
        """读取/proc/stat获取系统CPU统计"""
        cpu_stats = {}
        try:
            with open("/proc/stat") as f:
                for line in f:
                    if line.startswith("cpu "):
                        fields = line.split()
                        # user nice system idle iowait irq softirq steal guest guest_nice
                        vals = [int(x) for x in fields[1:]]
                        cpu_stats["user"] = vals[0]
                        cpu_stats["nice"] = vals[1]
                        cpu_stats["system"] = vals[2]
                        cpu_stats["idle"] = vals[3]
                        cpu_stats["iowait"] = vals[4]
                        cpu_stats["irq"] = vals[5]
                        cpu_stats["softirq"] = vals[6]
                        cpu_stats["total"] = sum(vals)
                    elif line.startswith("procs_running"):
                        cpu_stats["procs_running"] = int(line.split()[1])
                    elif line.startswith("ctxt"):
                        cpu_stats["context_switches"] = int(line.split()[1])
        except (FileNotFoundError, IndexError, ValueError):
            pass
        return cpu_stats

    def _read_proc_meminfo(self) -> dict:
        """读取/proc/meminfo获取内存统计"""
        mem = {}
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split()
                    key = parts[0].rstrip(":")
                    value = int(parts[1])  # in kB
                    mem[key] = value
        except (FileNotFoundError, IndexError, ValueError):
            pass
        return mem

    def _get_cpu_count(self) -> int:
        """获取CPU核心数"""
        try:
            return len(os.sched_getaffinity(0))
        except (AttributeError, OSError):
            try:
                return os.cpu_count() or 1
            except:
                return 1