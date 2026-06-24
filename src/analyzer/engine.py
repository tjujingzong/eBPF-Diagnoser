"""分析引擎

整合异常检测、规则推理、多维关联分析
"""

import logging
from typing import List, Optional
from datetime import datetime

from src.analyzer.anomaly import Anomaly, AnomalyType, Severity, EvidenceStep, RootCause
from src.analyzer.rules import RuleEngine
from src.collector.aggregator import MetricsAggregator

logger = logging.getLogger("ebpf-diagnoser.analyzer")


class CorrelationEngine:
    """跨场景关联分析引擎"""

    def correlate(self, anomalies: List[Anomaly], metrics: dict) -> List[Anomaly]:
        """对已检测到的异常进行跨场景关联分析

        关联规则:
        1. I/O异常 + 高iowait → I/O导致CPU等待
        2. 内存压力 + I/O延迟 → 换页导致I/O延迟
        3. 锁竞争 + CPU高 → 锁争用增加CPU上下文切换开销
        4. 内存压力 + 锁竞争 → 内存分配锁争用

        Args:
            anomalies: 已检测到的异常列表
            metrics: 当前指标

        Returns:
            增强后的异常列表(可能修改root_cause和evidence_chain)
        """
        if len(anomalies) < 2:
            return anomalies

        anomaly_types = {a.type for a in anomalies}

        # CPU + I/O 关联
        if AnomalyType.CPU_ANOMALY in anomaly_types and AnomalyType.IO_ANOMALY in anomaly_types:
            cpu_metrics = metrics.get("cpu", {}).get("global", {})
            io_wait = cpu_metrics.get("cpu_iowait_percent", 0)
            if io_wait > 20:
                # I/O等待导致CPU iowait升高
                for a in anomalies:
                    if a.type == AnomalyType.CPU_ANOMALY:
                        a.evidence_chain.append(EvidenceStep(
                            step=len(a.evidence_chain) + 1,
                            description=f"I/O等待占比{iowait:.1f}%，CPU iowait异常，疑似I/O瓶颈导致的CPU等待",
                            metric="cpu.global.cpu_iowait_percent",
                            value=io_wait,
                            baseline=None,
                        ))
                        if a.root_cause and "cpu_intensive" in a.root_cause.category:
                            a.root_cause.description = "I/O延迟导致CPU陷入iowait等待"
                            a.root_cause.category = "cpu_io_wait"
                            a.root_cause.confidence = min(a.root_cause.confidence + 0.05, 0.99)

        # 内存 + I/O 关联
        if AnomalyType.MEMORY_ANOMALY in anomaly_types and AnomalyType.IO_ANOMALY in anomaly_types:
            mem_metrics = metrics.get("mem", {}).get("system", {})
            pswpin = mem_metrics.get("pswpin_per_sec", 0)
            pswpout = mem_metrics.get("pswpout_per_sec", 0)
            if pswpin + pswpout > 10:
                for a in anomalies:
                    if a.type == AnomalyType.IO_ANOMALY:
                        a.evidence_chain.append(EvidenceStep(
                            step=len(a.evidence_chain) + 1,
                            description=f"换页活动频繁(pswpin={pswpin}/s, pswpout={pswpout}/s)，内存压力导致I/O延迟",
                            metric="mem.system.pswpin_per_sec",
                            value=pswpin,
                        ))
                        if a.root_cause:
                            a.root_cause.description = "内存压力导致频繁换页，引发I/O延迟"
                            a.root_cause.category = "memory_induced_io"

        # 锁 + CPU 关联
        if AnomalyType.LOCK_ANOMALY in anomaly_types and AnomalyType.CPU_ANOMALY in anomaly_types:
            cpu_metrics = metrics.get("cpu", {}).get("global", {})
            ctx_sw = cpu_metrics.get("context_switches_per_sec", 0)
            if ctx_sw > 20000:
                for a in anomalies:
                    if a.type == AnomalyType.CPU_ANOMALY:
                        a.evidence_chain.append(EvidenceStep(
                            step=len(a.evidence_chain) + 1,
                            description=f"锁竞争与高频上下文切换({ctx_sw}/s)关联，锁争用增加CPU调度开销",
                            metric="cpu.global.context_switches_per_sec",
                            value=ctx_sw,
                        ))

        # 内存 + 锁 关联 (新增: 内存分配锁争用)
        if AnomalyType.MEMORY_ANOMALY in anomaly_types and AnomalyType.LOCK_ANOMALY in anomaly_types:
            mem_metrics = metrics.get("mem", {}).get("system", {})
            pgfault = mem_metrics.get("pgfault_per_sec", 0)
            if pgfault > 50000:
                for a in anomalies:
                    if a.type == AnomalyType.LOCK_ANOMALY:
                        a.evidence_chain.append(EvidenceStep(
                            step=len(a.evidence_chain) + 1,
                            description=f"高频缺页({pgfault}/s)与锁竞争关联，疑似内存分配锁争用加剧",
                            metric="mem.system.pgfault_per_sec",
                            value=pgfault,
                        ))
                        if a.root_cause:
                            a.root_cause.description = "内存压力导致频繁page fault，引发内存分配锁争用"
                            a.root_cause.category = "memory_induced_lock_contention"
                            a.root_cause.confidence = min(a.root_cause.confidence + 0.05, 0.99)

        # CPU + Syscall 关联 (新增: 高频syscall导致CPU飙高)
        if AnomalyType.SYSCALL_ANOMALY in anomaly_types and AnomalyType.CPU_ANOMALY in anomaly_types:
            syscall_metrics = metrics.get("syscall", {}).get("global", {})
            total_syscalls = syscall_metrics.get("total_syscalls", 0)
            if total_syscalls > 100000:
                for a in anomalies:
                    if a.type == AnomalyType.CPU_ANOMALY:
                        a.evidence_chain.append(EvidenceStep(
                            step=len(a.evidence_chain) + 1,
                            description=f"高频系统调用({total_syscalls})与CPU高占用关联，syscall开销导致CPU饱和",
                            metric="syscall.global.total_syscalls",
                            value=total_syscalls,
                        ))
                        if a.root_cause and "cpu_intensive" in a.root_cause.category:
                            a.root_cause.description = "高频系统调用导致CPU开销增加"
                            a.root_cause.category = "cpu_syscall_overhead"
                            a.root_cause.confidence = min(a.root_cause.confidence + 0.05, 0.99)

        return anomalies


class AnalyzerEngine:
    """分析引擎主类

    工作流程:
    1. 接收指标快照
    2. 规则引擎评估异常
    3. 跨场景关联分析
    4. 返回异常列表
    """

    def __init__(self, config=None):
        self.rule_engine = RuleEngine(config)
        self.correlation = CorrelationEngine()
        self._last_anomalies = []
        self._anomaly_history = []
        # 异常抑制：同一类异常在N秒内不重复报
        self._suppression_window = 30  # 秒
        self._last_anomaly_time = {}  # type -> timestamp

    def analyze(self, snapshot: dict) -> List[Anomaly]:
        """分析指标快照

        Args:
            snapshot: 包含 metrics, baseline, timestamp 的快照

        Returns:
            检测到的异常列表
        """
        if not snapshot or "metrics" not in snapshot:
            return []

        metrics = snapshot["metrics"]
        baseline = snapshot.get("baseline", {})

        # Step 1: 规则引擎评估
        anomalies = self.rule_engine.evaluate(metrics, baseline)

        if not anomalies:
            return []

        # Step 2: 跨场景关联分析
        anomalies = self.correlation.correlate(anomalies, metrics)

        # Step 3: 异常抑制(同类异常在窗口期内不重复报)
        now = datetime.now().timestamp()
        filtered = []
        for anomaly in anomalies:
            last_time = self._last_anomaly_time.get(anomaly.type, 0)
            if now - last_time > self._suppression_window:
                filtered.append(anomaly)
                self._last_anomaly_time[anomaly.type] = now
                self._anomaly_history.append(anomaly)

        # Step 4: 更新时间窗口
        for anomaly in filtered:
            anomaly.time_window["start"] = datetime.fromtimestamp(
                now - self._suppression_window
            ).strftime("%Y-%m-%dT%H:%M:%S")
            anomaly.time_window["end"] = datetime.fromtimestamp(
                now
            ).strftime("%Y-%m-%dT%H:%M:%S")

        self._last_anomalies = filtered
        return filtered

    def get_history(self, limit: int = 100) -> List[Anomaly]:
        """获取历史异常记录"""
        return self._anomaly_history[-limit:]