"""规则引擎

基于YAML配置的规则引擎，用于异常检测和根因推理
"""

import yaml
import os
from typing import List, Dict, Any, Optional
from src.analyzer.anomaly import Anomaly, AnomalyType, Severity, EvidenceStep, AffectedObject, RootCause


class Rule:
    """单条检测规则"""

    def __init__(self, name: str, conditions: list, anomaly_type: str,
                 severity: str, root_cause: dict, recommendations: list,
                 config=None):
        self.name = name
        self.conditions = conditions  # [{'metric': 'cpu_usage', 'op': '>', 'value': 90, 'duration': 3}]
        self.anomaly_type = AnomalyType(anomaly_type)
        self.severity = Severity(severity)
        self.root_cause_template = root_cause
        self.recommendations = recommendations
        self.config = config

    def _resolve_threshold(self, cond: dict) -> float:
        """动态解析阈值：优先从config获取，支持threshold_key引用"""
        threshold_key = cond.get("threshold_key")
        if threshold_key and self.config and hasattr(self.config.thresholds, threshold_key):
            val = getattr(self.config.thresholds, threshold_key)
            factor = cond.get("threshold_factor", 1.0)
            return val * factor
        return cond.get("value", 0)

    def evaluate(self, metrics: dict, baseline: dict) -> Optional[Anomaly]:
        """评估规则是否触发

        Args:
            metrics: 当前指标快照
            baseline: 动态基线

        Returns:
            触发则返回Anomaly, 否则None
        """
        evidence_steps = []
        all_matched = True
        step = 0

        for cond in self.conditions:
            step += 1
            metric_path = cond["metric"]
            op = cond.get("op", ">")
            threshold = self._resolve_threshold(cond)
            use_baseline = cond.get("use_baseline", False)
            description = cond.get("description", f"{metric_path} {op} {threshold}")

            # 获取指标值
            value = self._get_nested(metrics, metric_path)
            if value is None:
                all_matched = False
                continue

            # 判断条件
            if use_baseline and metric_path in baseline:
                bl = baseline[metric_path]
                baseline_mean = bl.get("mean", 0)
                baseline_stdev = bl.get("stdev", 0)
                if baseline_stdev > 0:
                    threshold = baseline_mean + threshold * baseline_stdev  # threshold作为sigma倍数

            matched = self._compare(value, op, threshold)

            evidence_steps.append(EvidenceStep(
                step=step,
                description=description,
                metric=metric_path,
                value=value,
                baseline=baseline.get(metric_path, {}).get("mean") if metric_path in baseline else None,
            ))

            if not matched:
                all_matched = False

        if not all_matched:
            return None

        # 所有条件匹配，构建Anomaly
        return self._build_anomaly(metrics, evidence_steps, baseline)

    def _compare(self, value, op: str, threshold) -> bool:
        """比较操作"""
        try:
            if op == ">":
                return value > threshold
            elif op == ">=":
                return value >= threshold
            elif op == "<":
                return value < threshold
            elif op == "<=":
                return value <= threshold
            elif op == "==":
                return value == threshold
            elif op == "!=":
                return value != threshold
        except TypeError:
            return False
        return False

    def _get_nested(self, d: dict, path: str):
        """获取嵌套dict值, 支持 cpu.global.cpu_usage_percent"""
        keys = path.split(".")
        current = d
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current

    def _build_anomaly(self, metrics: dict, evidence: list, baseline: dict) -> Anomaly:
        """构建异常事件"""
        from datetime import datetime
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        # 从指标中提取受影响对象
        affected = self._extract_affected_objects(metrics)

        # 从指标中提取关键指标
        key_metrics = self._extract_key_metrics(metrics)

        # 构建根因
        rc = self.root_cause_template
        root_cause = RootCause(
            description=rc.get("description", ""),
            category=rc.get("category", self.anomaly_type.value),
            confidence=rc.get("confidence", 0.8),
            reasoning=rc.get("reasoning", ""),
        )

        return Anomaly(
            type=self.anomaly_type,
            severity=self.severity,
            confidence=0.85,
            time_window={"start": now, "end": now},
            affected_objects=affected,
            key_metrics=key_metrics,
            evidence_chain=evidence,
            root_cause=root_cause,
            recommendations=self.recommendations,
        )

    def _extract_affected_objects(self, metrics: dict) -> list:
        """从指标中提取受影响对象"""
        objects = []

        # 根据异常类型提取
        if self.anomaly_type == AnomalyType.CPU_ANOMALY:
            per_process = self._get_nested(metrics, "cpu.per_process")
            if per_process:
                # 取CPU最高的进程
                sorted_procs = sorted(per_process.values(), key=lambda x: x.get("cpu_percent", 0), reverse=True)
                for proc in sorted_procs[:3]:
                    objects.append(AffectedObject(
                        object_type="process",
                        pid=proc.get("pid"),
                        comm=proc.get("comm"),
                    ))

        elif self.anomaly_type == AnomalyType.IO_ANOMALY:
            devices = self._get_nested(metrics, "io.devices")
            if devices:
                for dev_id, dev_stat in devices.items():
                    objects.append(AffectedObject(
                        object_type="device",
                        device=dev_stat.get("device", str(dev_id)),
                    ))

        elif self.anomaly_type == AnomalyType.MEMORY_ANOMALY:
            per_process = self._get_nested(metrics, "mem.per_process")
            if per_process:
                for proc in per_process[:3]:  # already sorted by RSS
                    objects.append(AffectedObject(
                        object_type="process",
                        pid=proc.get("pid"),
                        comm=proc.get("comm"),
                    ))

        elif self.anomaly_type == AnomalyType.LOCK_ANOMALY:
            futex = self._get_nested(metrics, "lock.futex_per_process")
            if futex:
                sorted_procs = sorted(futex.values(), key=lambda x: x.get("avg_wait_ms", 0), reverse=True)
                for proc in sorted_procs[:3]:
                    objects.append(AffectedObject(
                        object_type="process",
                        pid=proc.get("pid"),
                        comm=proc.get("comm"),
                    ))

        elif self.anomaly_type == AnomalyType.SYSCALL_ANOMALY:
            per_syscall = self._get_nested(metrics, "syscall.per_syscall")
            if per_syscall:
                sorted_sys = sorted(per_syscall.values(), key=lambda x: x.get("calls_per_sec", 0), reverse=True)
                for sc in sorted_sys[:3]:
                    objects.append(AffectedObject(
                        object_type="syscall",
                        syscall_name=sc.get("name"),
                    ))

        return objects

    def _extract_key_metrics(self, metrics: dict) -> dict:
        """提取关键指标"""
        key_metrics = {}
        metric_paths = {
            AnomalyType.CPU_ANOMALY: [
                "cpu.global.cpu_usage_percent", "cpu.global.context_switches_per_sec",
                "cpu.global.runqueue_length",
            ],
            AnomalyType.IO_ANOMALY: [
                "io.global.p99_latency_ms",
            ],
            AnomalyType.MEMORY_ANOMALY: [
                "mem.system.available_percent", "mem.system.used_percent",
                "mem.events.direct_reclaim_per_sec", "mem.events.kswapd_wake_per_sec",
            ],
            AnomalyType.LOCK_ANOMALY: [
                "lock.global.total_futex_wait_ms",
            ],
            AnomalyType.SYSCALL_ANOMALY: [
                "syscall.global.total_syscalls",
            ],
        }

        for path in metric_paths.get(self.anomaly_type, []):
            value = self._get_nested(metrics, path)
            if value is not None:
                key_metrics[path.split(".")[-1]] = value

        return key_metrics


class RuleEngine:
    """规则引擎"""

    def __init__(self, config=None):
        self.rules: List[Rule] = []
        self.config = config
        self._load_default_rules()
        if config:
            self._load_config_rules(config)

    def _th(self, attr: str, default: float) -> float:
        """从配置获取阈值，无配置时返回默认值"""
        if self.config and hasattr(self.config.thresholds, attr):
            return getattr(self.config.thresholds, attr)
        return default

    def _load_default_rules(self):
        """加载内置默认规则"""
        # ===== CPU异常规则 =====
        self.rules.append(Rule(
            name="cpu_intensive_compute",
            conditions=[
                {"metric": "cpu.global.cpu_usage_percent", "op": ">", "value": self._th("cpu_usage_high", 90),
                 "threshold_key": "cpu_usage_high",
                 "description": "CPU使用率持续高于阈值"},
            ],
            anomaly_type="cpu_anomaly",
            severity="high",
            root_cause={
                "description": "用户态计算热点导致CPU饱和",
                "category": "cpu_intensive_compute",
                "confidence": 0.85,
                "reasoning": "CPU使用率持续高于90%，存在CPU密集型进程",
            },
            recommendations=[
                "检查高CPU占用进程是否为预期业务",
                "使用perf record进一步定位热点函数",
                "考虑通过cgroup限制CPU配额",
            ],
            config=self.config,
        ))

        self.rules.append(Rule(
            name="cpu_thread_contention",
            conditions=[
                {"metric": "cpu.global.cpu_usage_percent", "op": ">", "value": self._th("cpu_usage_warn", 70),
                 "threshold_key": "cpu_usage_warn",
                 "description": "CPU使用率偏高"},
                {"metric": "cpu.global.context_switches_per_sec", "op": ">", "value": 30000,
                 "description": "上下文切换率异常升高"},
            ],
            anomaly_type="cpu_anomaly",
            severity="medium",
            root_cause={
                "description": "多线程竞争导致CPU开销增加",
                "category": "cpu_thread_contention",
                "confidence": 0.75,
                "reasoning": "高CPU伴随高频上下文切换，表明线程竞争激烈",
            },
            recommendations=[
                "检查高切换进程的线程模型",
                "使用perf sched分析调度延迟",
                "考虑减少线程数或优化锁粒度",
            ],
            config=self.config,
        ))

        # CPU调度延迟规则 (新增: 基于sched_wakeup → sched_switch延迟)
        self.rules.append(Rule(
            name="cpu_sched_latency_high",
            conditions=[
                {"metric": "cpu.global.sched_avg_latency_ms", "op": ">", "value": self._th("sched_delay_high", 50),
                 "threshold_key": "sched_delay_high",
                 "description": "平均调度延迟过高"},
            ],
            anomaly_type="cpu_anomaly",
            severity="high",
            root_cause={
                "description": "进程唤醒后长时间等待调度，存在CPU饱和或优先级倒置",
                "category": "cpu_sched_latency",
                "confidence": 0.80,
                "reasoning": "调度延迟反映从wakeup到switch的等待时间，过高说明runqueue拥堵或CPU资源不足",
            },
            recommendations=[
                "检查runqueue长度是否持续偏高",
                "使用perf sched record分析调度热点",
                "评估是否需要增加CPU核心或调整nice值",
            ],
            config=self.config,
        ))

        # ===== I/O异常规则 =====
        self.rules.append(Rule(
            name="io_queue_congestion",
            conditions=[
                {"metric": "io.global.p99_latency_ms", "op": ">", "value": self._th("io_p99_high", 50),
                 "threshold_key": "io_p99_high",
                 "description": "I/O P99延迟异常升高"},
            ],
            anomaly_type="io_anomaly",
            severity="high",
            root_cause={
                "description": "磁盘队列拥堵导致I/O延迟抖动",
                "category": "io_queue_congestion",
                "confidence": 0.80,
                "reasoning": "P99延迟显著升高，表明I/O请求积压严重",
            },
            recommendations=[
                "检查I/O密集进程和热点文件",
                "考虑使用iostat -x 1进一步分析",
                "评估是否需要增加I/O带宽或使用更快的存储",
            ],
            config=self.config,
        ))

        # ===== 内存异常规则 =====
        self.rules.append(Rule(
            name="memory_pressure",
            conditions=[
                {"metric": "mem.system.available_percent", "op": "<", "value": self._th("mem_available_low", 10),
                 "threshold_key": "mem_available_low",
                 "description": "可用内存低于阈值"},
            ],
            anomaly_type="memory_anomaly",
            severity="high",
            root_cause={
                "description": "内存不足导致系统压力升高",
                "category": "memory_pressure",
                "confidence": 0.90,
                "reasoning": "可用内存持续下降，系统面临内存压力",
            },
            recommendations=[
                "检查内存占用最高的进程",
                "考虑增加swap空间或物理内存",
                "评估是否存在内存泄漏",
            ],
            config=self.config,
        ))

        self.rules.append(Rule(
            name="memory_oom_risk",
            conditions=[
                {"metric": "mem.system.available_percent", "op": "<", "value": self._th("mem_available_low", 10) / 2,
                 "threshold_key": "mem_available_low", "threshold_factor": 0.5,
                 "description": "可用内存极低，有OOM风险"},
                {"metric": "mem.events.oom_kill_total", "op": ">", "value": 0,
                 "description": "已发生OOM kill事件"},
            ],
            anomaly_type="memory_anomaly",
            severity="critical",
            root_cause={
                "description": "内存即将耗尽，已触发OOM Killer",
                "category": "memory_oom_risk",
                "confidence": 0.95,
                "reasoning": "可用内存极低且OOM Killer已介入，系统内存严重不足",
            },
            recommendations=[
                "立即排查内存泄漏进程",
                "考虑紧急释放非关键进程内存",
                "调整vm.overcommit_memory和OOM策略",
            ],
            config=self.config,
        ))

        # ===== 锁竞争规则 =====
        self.rules.append(Rule(
            name="lock_contention",
            conditions=[
                {"metric": "lock.global.total_futex_wait_ms", "op": ">", "value": self._th("lock_wait_high", 10) * 10,
                 "threshold_key": "lock_wait_high", "threshold_factor": 10.0,
                 "description": "futex等待时间过长"},
            ],
            anomaly_type="lock_anomaly",
            severity="medium",
            root_cause={
                "description": "锁竞争导致性能退化",
                "category": "lock_contention",
                "confidence": 0.75,
                "reasoning": "futex等待时间异常，存在锁热点争用",
            },
            recommendations=[
                "使用perf lock分析锁热点",
                "检查热点锁的临界区大小",
                "考虑优化锁粒度或使用无锁数据结构",
            ],
            config=self.config,
        ))

        # ===== 系统调用异常规则 =====
        self.rules.append(Rule(
            name="syscall_polling",
            conditions=[
                {"metric": "syscall.global.total_syscalls", "op": ">", "value": 5000,
                 "description": "系统调用频率异常升高"},
            ],
            anomaly_type="syscall_anomaly",
            severity="low",
            root_cause={
                "description": "高频系统调用可能存在轮询行为",
                "category": "syscall_polling",
                "confidence": 0.60,
                "reasoning": "系统调用频率显著高于基线，可能存在无效轮询",
            },
            recommendations=[
                "检查高频syscall类型和调用进程",
                "评估是否可将轮询替换为事件驱动",
            ],
            config=self.config,
        ))

    def _load_config_rules(self, config):
        """从配置文件加载自定义规则"""
        rules_dir = os.path.join(os.path.dirname(__file__), "..", "..", "rules")
        for filename in os.listdir(rules_dir):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                try:
                    with open(os.path.join(rules_dir, filename)) as f:
                        rules_data = yaml.safe_load(f)
                        if rules_data and "rules" in rules_data:
                            for r in rules_data["rules"]:
                                self.rules.append(Rule(
                                    name=r["name"],
                                    conditions=r["conditions"],
                                    anomaly_type=r["anomaly_type"],
                                    severity=r.get("severity", "medium"),
                                    root_cause=r.get("root_cause", {}),
                                    recommendations=r.get("recommendations", []),
                                ))
                except Exception as e:
                    pass  # 规则加载失败不阻塞

    def evaluate(self, metrics: dict, baseline: dict) -> List[Anomaly]:
        """评估所有规则"""
        anomalies = []
        for rule in self.rules:
            anomaly = rule.evaluate(metrics, baseline)
            if anomaly:
                anomalies.append(anomaly)
        return anomalies