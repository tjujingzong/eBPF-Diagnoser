"""探针管理模块

管理所有eBPF探针的加载、指标轮询和卸载
"""

from src.probes.cpu_probe import CpuProbe
from src.probes.io_probe import IoProbe
from src.probes.mem_probe import MemProbe
from src.probes.lock_probe import LockProbe
from src.probes.syscall_probe import SyscallProbe
from src.probes.base import BaseProbe

PROBE_REGISTRY = {
    "cpu": CpuProbe,
    "io": IoProbe,
    "mem": MemProbe,
    "lock": LockProbe,
    "syscall": SyscallProbe,
}


class ProbeManager:
    """探针管理器：统一加载/轮询/卸载所有探针"""

    def __init__(self, probe_names: list, config):
        self.config = config
        self.probes: dict[str, BaseProbe] = {}
        for name in probe_names:
            if name not in PROBE_REGISTRY:
                raise ValueError(f"未知探针: {name}, 可选: {list(PROBE_REGISTRY.keys())}")
            self.probes[name] = PROBE_REGISTRY[name](config)

    def attach_all(self):
        """加载并挂载所有探针"""
        for name, probe in self.probes.items():
            probe.attach()
            # apply sample rate
            probe.set_sample_rate(getattr(self.config.probe, f"{name}_sample_rate", 1))

    def detach_all(self):
        """卸载所有探针"""
        for name, probe in self.probes.items():
            try:
                probe.detach()
            except Exception as e:
                # detach时不抛异常,确保所有探针都能被清理
                pass

    def poll_metrics(self) -> dict:
        """轮询所有探针的指标"""
        all_metrics = {}
        for name, probe in self.probes.items():
            try:
                metrics = probe.poll()
                if metrics:
                    all_metrics[name] = metrics
            except Exception as e:
                # 单个探针故障不影响其他探针
                pass
        return all_metrics

    def get_overhead(self) -> dict:
        """获取工具自身的性能开销"""
        overhead = {}
        for name, probe in self.probes.items():
            overhead[name] = probe.get_overhead()
        return overhead