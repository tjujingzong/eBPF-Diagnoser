"""I/O延迟抖动探针

检测: I/O延迟异常、队列拥堵、热点设备
tracepoint: block:block_rq_issue, block:block_rq_complete
"""

import time
from src.probes.base import BaseProbe


class IoProbe(BaseProbe):
    """I/O延迟抖动探针"""

    def __init__(self, config):
        super().__init__(config)
        self._prev_dev_stats = {}
        self._prev_timestamp = None

    def get_bpf_obj_name(self) -> str:
        return "io_probe.bpf.o"

    def poll(self) -> dict:
        """轮询I/O指标"""
        now = time.time()
        metrics = {"devices": {}, "global": {}}

        # 1. 从BPF MAP获取每设备统计
        dev_data = {}
        try:
            for entry in self._read_hash("dev_stats", max_entries=256):
                dev_key = entry["key"]
                val = entry["value"]
                dev_data[dev_key] = {
                    "read_count": val.get("read_count", 0),
                    "write_count": val.get("write_count", 0),
                    "total_latency_ns": val.get("total_latency_ns", 0),
                    "io_count": val.get("io_count", 0),
                    "queue_depth": val.get("queue_depth", 0),
                }
        except Exception:
            pass

        # 2. 延迟直方图
        latency_hist = {}
        try:
            for entry in self._read_hash("lat_hist", max_entries=64):
                bucket = entry["key"]
                count = entry["value"]
                latency_hist[bucket] = count
        except Exception:
            pass

        # 3. 计算P99
        p99_ns = self._calc_percentile(latency_hist, 0.99)
        metrics["global"]["p99_latency_ms"] = round(p99_ns / 1e6, 2)

        # 4. 增量指标
        if self._prev_dev_stats and self._prev_timestamp:
            dt = now - self._prev_timestamp
            if dt > 0:
                for dev_key, curr in dev_data.items():
                    prev = self._prev_dev_stats.get(dev_key, {})
                    io_delta = curr["io_count"] - prev.get("io_count", 0)
                    latency_delta = curr["total_latency_ns"] - prev.get("total_latency_ns", 0)

                    iops = io_delta / dt if dt > 0 else 0
                    avg_latency_ms = (latency_delta / io_delta / 1e6) if io_delta > 0 else 0

                    metrics["devices"][dev_key] = {
                        "iops": round(iops, 1),
                        "avg_latency_ms": round(avg_latency_ms, 2),
                        "queue_depth": curr["queue_depth"],
                    }

        self._prev_dev_stats = dev_data
        self._prev_timestamp = now
        return metrics

    def _calc_percentile(self, hist: dict, percentile: float) -> float:
        """从log2直方图计算百分位延迟"""
        if not hist:
            return 0
        total = sum(hist.values())
        if total == 0:
            return 0
        target = total * percentile
        cumulative = 0
        for bucket in sorted(hist.keys()):
            cumulative += hist[bucket]
            if cumulative >= target:
                return 2**bucket
        return 2 ** max(hist.keys())
