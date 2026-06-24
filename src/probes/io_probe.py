"""I/O延迟抖动探针

检测: I/O延迟异常、队列拥堵、热点设备
tracepoint: block:block_rq_issue, block:block_rq_complete
"""

import time
import os
from collections import defaultdict
from src.probes.base import BaseProbe


IO_BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

// I/O请求追踪 - 使用sector作为key
BPF_HASH(io_start, u64, u64);   // sector -> start_timestamp

// 每设备统计
struct io_dev_stat {
    u64 read_count;
    u64 write_count;
    u64 total_latency_ns;
    u64 io_count;
    u32 queue_depth;
};

BPF_HASH(dev_stats, u32, struct io_dev_stat);

// 延迟直方图 (log2分桶)
BPF_ARRAY(lat_hist, u64, 64);

// block_rq_issue: I/O请求发出
TRACEPOINT_PROBE(block, block_rq_issue) {
    u64 ts = bpf_ktime_get_ns();
    u64 sector = args->sector;

    // 记录请求开始时间
    io_start.update(&sector, &ts);

    // 判断读写: rwbs[0] == 'W' 表示写, 'R' 表示读
    u8 is_write = (args->rwbs[0] == 'W');

    // 队列深度+1
    u32 dev_key = args->dev & 0xFFFF;  // 简化设备号
    struct io_dev_stat *stat = dev_stats.lookup(&dev_key);
    if (stat) {
        stat->queue_depth += 1;
        stat->read_count += is_write ? 0 : 1;
        stat->write_count += is_write ? 1 : 0;
    } else {
        struct io_dev_stat new_stat = {};
        new_stat.queue_depth = 1;
        new_stat.read_count = is_write ? 0 : 1;
        new_stat.write_count = is_write ? 1 : 0;
        dev_stats.update(&dev_key, &new_stat);
    }

    return 0;
}

// block_rq_complete: I/O完成
TRACEPOINT_PROBE(block, block_rq_complete) {
    u64 ts = bpf_ktime_get_ns();
    u64 sector = args->sector;

    // 查找开始时间
    u64 *start_ts = io_start.lookup(&sector);
    if (!start_ts) {
        return 0;
    }

    u64 latency_ns = ts - *start_ts;
    io_start.delete(&sector);

    // 更新设备统计
    u32 dev_key = args->dev & 0xFFFF;
    struct io_dev_stat *stat = dev_stats.lookup(&dev_key);
    if (stat) {
        stat->io_count += 1;
        stat->total_latency_ns += latency_ns;
        if (stat->queue_depth > 0) {
            stat->queue_depth -= 1;
        }
    }

    // 更新延迟直方图
    u32 bucket = 0;
    if (latency_ns > 0) {
        // log2近似
        u64 val = latency_ns;
        while (val > 1) {
            val >>= 1;
            bucket += 1;
        }
    }
    u64 *count = lat_hist.lookup(&bucket);
    if (count) {
        (*count) += 1;
    } else {
        u64 one = 1;
        lat_hist.update(&bucket, &one);
    }

    return 0;
}
"""


class IoProbe(BaseProbe):
    """I/O延迟抖动探针"""

    def __init__(self, config):
        super().__init__(config)
        self._prev_dev_stats = {}
        self._prev_timestamp = None

    def get_bpf_text(self) -> str:
        return IO_BPF_TEXT.replace("__SAMPLE_RATE__", str(self.sample_rate))

    def _attach_tracepoints(self):
        """block tracepoint由BCC自动挂载"""
        pass

    def poll(self) -> dict:
        """轮询I/O指标"""
        now = time.time()
        metrics = {"devices": {}, "global": {}}

        # 1. 从BPF MAP获取每设备统计
        dev_data = {}
        try:
            for key, val in self.bpf["dev_stats"].items():
                dev_key = key.value
                dev_data[dev_key] = {
                    "read_count": val.read_count,
                    "write_count": val.write_count,
                    "total_latency_ns": val.total_latency_ns,
                    "io_count": val.io_count,
                    "queue_depth": val.queue_depth,
                }
        except Exception:
            pass

        # 2. 延迟直方图
        latency_hist = {}
        try:
            for key, val in self.bpf["lat_hist"].items():
                bucket = key.value
                latency_hist[bucket] = val.value
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
                return 2 ** bucket
        return 2 ** max(hist.keys())