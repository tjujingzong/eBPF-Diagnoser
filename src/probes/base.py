"""探针基类

所有eBPF探针的抽象基类，定义统一接口。
使用libbpf + CO-RE方案，通过C bpf_loader进程加载和读取BPF程序。
"""

import os
import time
import resource
import logging
from abc import ABC, abstractmethod
from typing import Optional

from src.probes.bpf_loader import BpfLoader

logger = logging.getLogger(__name__)

# BPF .o 文件的默认搜索路径
_BPF_OBJ_SEARCH_PATHS = [
    os.path.join(os.path.dirname(__file__), "..", "..", "build", "bpf"),
    os.path.join(os.path.dirname(__file__), "..", "..", "bpf"),
    "/opt/ebpf-diagnoser/bpf",
]


def find_bpf_obj(name: str) -> str:
    """查找预编译的BPF .o文件路径"""
    for base in _BPF_OBJ_SEARCH_PATHS:
        path = os.path.normpath(os.path.join(base, name))
        if os.path.isfile(path):
            return path
    raise FileNotFoundError(
        f"BPF对象文件 '{name}' 未找到。请先运行 'make bpf' 编译。"
        f"搜索路径: {_BPF_OBJ_SEARCH_PATHS}"
    )


class BaseProbe(ABC):
    """eBPF探针基类"""

    def __init__(self, config):
        self.config = config
        self.sample_rate = 1
        self._start_time = None
        self._start_cpu_time = None
        self._attached = False
        self._loader = None
        self._obj_index = -1

    @abstractmethod
    def get_bpf_obj_name(self) -> str:
        """返回预编译的BPF .o文件名，如 'cpu_probe.bpf.o'"""
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
        self._loader = BpfLoader.get_instance()
        obj_path = find_bpf_obj(self.get_bpf_obj_name())

        result = self._loader.send({
            "cmd": "LOAD",
            "obj_path": obj_path,
            "sample_rate": self.sample_rate,
        })
        if not result.get("ok"):
            raise RuntimeError(f"BPF加载失败 ({self.get_bpf_obj_name()}): {result.get('error')}")
        self._obj_index = result.get("obj_index", -1)

        result = self._loader.send({
            "cmd": "ATTACH",
            "obj_index": self._obj_index,
        })
        if not result.get("ok"):
            raise RuntimeError(f"BPF挂载失败 ({self.get_bpf_obj_name()}): {result.get('error')}")

        self._start_time = time.time()
        self._start_cpu_time = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        self._attached = True
        logger.info("探针已挂载: %s (attached=%d programs)",
                     self.get_bpf_obj_name(), result.get("attached", 0))

    def detach(self):
        """卸载BPF程序"""
        if self._loader and self._obj_index >= 0:
            try:
                self._loader.send({
                    "cmd": "DETACH",
                    "obj_index": self._obj_index,
                })
            except Exception as e:
                logger.warning("BPF卸载异常: %s", e)
            self._obj_index = -1
        self._attached = False

    def set_sample_rate(self, rate: int):
        """设置采样率 (1=全采样, N=1/N采样)"""
        self.sample_rate = max(1, rate)

    def _read_array(self, map_name: str, index: int = 0) -> dict:
        """读取BPF ARRAY map的元素"""
        if not self._loader or self._obj_index < 0:
            return {}
        result = self._loader.send({
            "cmd": "READ_MAP_ARRAY",
            "obj_index": self._obj_index,
            "map": map_name,
            "index": index,
        })
        if result.get("ok"):
            return result.get("data", {})
        logger.debug("READ_MAP_ARRAY 失败: %s - %s", map_name, result.get("error"))
        return {}

    def _read_hash(self, map_name: str, max_entries: int = 256) -> list:
        """读取BPF HASH map的全部条目，返回 [{key, value}, ...]"""
        if not self._loader or self._obj_index < 0:
            return []
        result = self._loader.send({
            "cmd": "READ_MAP_HASH",
            "obj_index": self._obj_index,
            "map": map_name,
            "max_entries": max_entries,
        })
        if result.get("ok"):
            return result.get("entries", [])
        logger.debug("READ_MAP_HASH 失败: %s - %s", map_name, result.get("error"))
        return []

    def _read_stack(self, map_name: str, stack_id: int) -> list:
        """读取栈追踪，返回地址列表"""
        if not self._loader or self._obj_index < 0:
            return []
        result = self._loader.send({
            "cmd": "READ_STACK",
            "obj_index": self._obj_index,
            "map": map_name,
            "stack_id": stack_id,
        })
        if result.get("ok"):
            return result.get("addrs", [])
        return []

    def _resolve_ksyms(self, addrs: list) -> list:
        """批量解析内核地址为符号名"""
        if not self._loader or not addrs:
            return ["??"] * len(addrs)
        result = self._loader.send({
            "cmd": "RESOLVE_KSYM",
            "addrs": addrs,
        })
        if result.get("ok"):
            return result.get("symbols", ["??"] * len(addrs))
        return ["??"] * len(addrs)

    def get_overhead(self) -> dict:
        """获取探针自身的CPU和内存开销"""
        if not self._attached:
            return {"cpu_percent": 0, "memory_mb": 0}

        current_cpu = resource.getrusage(resource.RUSAGE_SELF).ru_utime
        elapsed = time.time() - self._start_time if self._start_time else 1
        cpu_percent = (current_cpu - self._start_cpu_time) / elapsed * 100 if elapsed > 0 else 0

        with open("/proc/self/status") as f:
            memory_mb = 0
            for line in f:
                if line.startswith("VmRSS:"):
                    memory_mb = int(line.split()[1]) / 1024
                    break

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
                    value = int(parts[1])
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
            except Exception:
                return 1
