"""指标聚合器

功能:
  - 滑动窗口时序聚合
  - 动态基线计算(3-sigma)
  - 指标快照管理
  - 系统信息采集
"""

import os
import time
import platform
from collections import deque
from typing import Optional
from statistics import mean, stdev


class MetricsWindow:
    """滑动窗口，存储最近N个采集周期的指标"""

    def __init__(self, size: int = 60):
        self.size = size
        self.data: deque = deque(maxlen=size)

    def push(self, metrics: dict, timestamp: float):
        """添加一条指标记录"""
        self.data.append({"timestamp": timestamp, "metrics": metrics})

    def get_recent(self, seconds: int = 30) -> list:
        """获取最近N秒的指标"""
        now = time.time()
        cutoff = now - seconds
        return [r for r in self.data if r["timestamp"] >= cutoff]

    def get_all(self) -> list:
        """获取所有指标"""
        return list(self.data)

    def latest(self) -> Optional[dict]:
        """获取最新一条"""
        return self.data[-1] if self.data else None


class DynamicBaseline:
    """动态基线，基于历史数据自适应调整阈值"""

    def __init__(self, warmup: int = 30, sigma: float = 3.0):
        """
        Args:
            warmup: 预热周期数(前N个样本用静态阈值)
            sigma: 异常判定倍数
        """
        self.warmup = warmup
        self.sigma = sigma
        self.history: dict[str, deque] = {}  # key -> deque of values
        self.history_size = 300  # 5分钟@1s间隔

    def update(self, metrics: dict, prefix: str = ""):
        """更新基线历史"""
        flat = self._flatten(metrics, prefix)
        for key, value in flat.items():
            if isinstance(value, (int, float)):
                if key not in self.history:
                    self.history[key] = deque(maxlen=self.history_size)
                self.history[key].append(value)

    def is_anomaly(self, key: str, value: float) -> bool:
        """判断指标值是否异常(3-sigma)"""
        if key not in self.history or len(self.history[key]) < self.warmup:
            return False  # 预热期不判异常

        values = list(self.history[key])
        avg = mean(values)
        std = stdev(values) if len(values) > 1 else 0

        if std == 0:
            return value > avg * 2  # 无波动时翻倍判定

        z_score = (value - avg) / std
        return abs(z_score) > self.sigma

    def get_baseline(self, key: str) -> dict:
        """获取指标的基线统计"""
        if key not in self.history or len(self.history[key]) < 2:
            return {"mean": 0, "stdev": 0, "samples": 0}

        values = list(self.history[key])
        return {
            "mean": round(mean(values), 4),
            "stdev": round(stdev(values), 4),
            "min": round(min(values), 4),
            "max": round(max(values), 4),
            "samples": len(values),
        }

    def _flatten(self, d: dict, prefix: str = "") -> dict:
        """将嵌套dict展平为key=value"""
        items = {}
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                items.update(self._flatten(v, key))
            elif isinstance(v, (int, float)):
                items[key] = v
            elif isinstance(v, list):
                # 列表类型的指标暂不处理
                pass
        return items


class MetricsAggregator:
    """指标聚合器主类"""

    def __init__(self, window_size: int = 60, interval: float = 1.0):
        self.window = MetricsWindow(window_size)
        self.baseline = DynamicBaseline(warmup=30, sigma=3.0)
        self.interval = interval
        self._system_info = None

    def update(self, metrics: dict):
        """更新指标"""
        now = time.time()
        self.window.push(metrics, now)
        self.baseline.update(metrics)

    def get_current_snapshot(self) -> dict:
        """获取当前快照(最新指标 + 基线)"""
        latest = self.window.latest()
        if not latest:
            return {}

        snapshot = {
            "timestamp": latest["timestamp"],
            "metrics": latest["metrics"],
            "baseline": {},
        }

        # 附加动态基线
        flat = self.baseline._flatten(latest["metrics"])
        for key in flat:
            snapshot["baseline"][key] = self.baseline.get_baseline(key)

        return snapshot

    def get_system_info(self) -> dict:
        """采集系统信息"""
        if self._system_info:
            return self._system_info

        info = {
            "hostname": platform.node(),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "os": platform.system(),
            "python_version": platform.python_version(),
        }

        # CPU信息
        try:
            info["cpu_count"] = os.cpu_count() or 1
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("model name"):
                        info["cpu_model"] = line.split(":")[1].strip()
                        break
        except (FileNotFoundError, StopIteration):
            pass

        # 内存信息
        mem = self._read_proc_meminfo()
        if mem:
            total_mb = mem.get("MemTotal", 0) // 1024
            info["memory_total_mb"] = total_mb

        self._system_info = info
        return info

    def _read_proc_meminfo(self) -> dict:
        """读取/proc/meminfo"""
        mem = {}
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0].rstrip(":")
                        try:
                            mem[key] = int(parts[1])
                        except ValueError:
                            pass
        except FileNotFoundError:
            pass
        return mem