"""输出格式化器

支持 JSON / YAML / Markdown / 终端表格 四种输出格式
"""

import json
import yaml
from datetime import datetime
from typing import List, Dict, Optional

from src.analyzer.anomaly import Anomaly


# ───────────────────── JSON输出 ─────────────────────

def format_json(anomalies: List[Anomaly], system_info: dict = None,
                duration: float = 0, overhead: dict = None) -> str:
    """格式化为JSON诊断报告"""
    report = {
        "version": "1.0",
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z"),
        "diagnosis_id": f"diag-{datetime.now().strftime('%Y%m%d-%H%M%S')}-001",
        "anomalies": [a.to_dict() for a in anomalies],
        "system_context": system_info or {},
        "tool_metadata": {
            "name": "ebpf-diagnoser",
            "version": "1.0.0",
            "probe_status": {},
            "overhead": overhead or {},
            "duration_seconds": round(duration, 1),
        },
    }
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


# ───────────────────── YAML输出 ─────────────────────

def format_yaml(anomalies: List[Anomaly], system_info: dict = None,
                duration: float = 0, overhead: dict = None) -> str:
    """格式化为YAML诊断报告"""
    report = {
        "version": "1.0",
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z"),
        "diagnosis_id": f"diag-{datetime.now().strftime('%Y%m%d-%H%M%S')}-001",
        "anomalies": [a.to_dict() for a in anomalies],
        "system_context": system_info or {},
        "tool_metadata": {
            "name": "ebpf-diagnoser",
            "version": "1.0.0",
            "probe_status": {},
            "overhead": overhead or {},
            "duration_seconds": round(duration, 1),
        },
    }
    return yaml.dump(report, default_flow_style=False, allow_unicode=True, sort_keys=False, default=str)


# ───────────────────── Markdown输出 ─────────────────────

def format_markdown(anomalies: List[Anomaly], system_info: dict = None,
                    duration: float = 0, overhead: dict = None) -> str:
    """格式化为Markdown诊断报告"""
    lines = []
    lines.append("# eBPF Diagnoser 诊断报告")
    lines.append("")
    lines.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**运行时长**: {duration:.1f}秒")
    lines.append(f"**检测异常数**: {len(anomalies)}")
    lines.append("")

    # 系统信息
    if system_info:
        lines.append("## 系统信息")
        lines.append("")
        lines.append(f"| 项目 | 值 |")
        lines.append(f"|------|-----|")
        lines.append(f"| 主机名 | {system_info.get('hostname', 'N/A')} |")
        lines.append(f"| 内核版本 | {system_info.get('kernel', 'N/A')} |")
        lines.append(f"| 架构 | {system_info.get('arch', 'N/A')} |")
        lines.append(f"| CPU核心 | {system_info.get('cpu_count', 'N/A')} |")
        lines.append(f"| 内存 | {system_info.get('memory_total_mb', 'N/A')} MB |")
        lines.append("")

    # 每个异常
    severity_emoji = {"low": "🟢", "medium": "🟡", "high": "🔴", "critical": "🚨"}
    type_names = {
        "cpu_anomaly": "CPU异常",
        "io_anomaly": "I/O异常",
        "memory_anomaly": "内存异常",
        "lock_anomaly": "锁竞争",
        "syscall_anomaly": "系统调用异常",
    }

    for i, anomaly in enumerate(anomalies, 1):
        emoji = severity_emoji.get(anomaly.severity.value, "⚠️")
        type_name = type_names.get(anomaly.type.value, anomaly.type.value)
        lines.append(f"## 异常 #{i}: {emoji} {type_name}")
        lines.append("")
        lines.append(f"**严重程度**: {anomaly.severity.value}")
        lines.append(f"**置信度**: {anomaly.confidence:.0%}")
        lines.append(f"**时间窗口**: {anomaly.time_window.get('start', 'N/A')} ~ {anomaly.time_window.get('end', 'N/A')}")
        lines.append("")

        # 受影响对象
        if anomaly.affected_objects:
            lines.append("### 受影响对象")
            lines.append("")
            for obj in anomaly.affected_objects:
                if obj.object_type == "process":
                    lines.append(f"- 进程 `{obj.comm}` (PID: {obj.pid})")
                elif obj.object_type == "device":
                    lines.append(f"- 设备 `{obj.device}`")
                elif obj.object_type == "syscall":
                    lines.append(f"- 系统调用 `{obj.syscall_name}`")
                else:
                    lines.append(f"- {obj.object_type}")
            lines.append("")

        # 关键指标
        if anomaly.key_metrics:
            lines.append("### 关键指标")
            lines.append("")
            lines.append("| 指标 | 值 |")
            lines.append("|------|-----|")
            for key, value in anomaly.key_metrics.items():
                lines.append(f"| {key} | {value} |")
            lines.append("")

        # 证据链
        if anomaly.evidence_chain:
            lines.append("### 证据链")
            lines.append("")
            for step in anomaly.evidence_chain:
                baseline_str = f" (基线: {step.baseline})" if step.baseline is not None else ""
                lines.append(f"{step.step}. {step.description}: {step.value}{baseline_str}")
            lines.append("")

        # 根因
        if anomaly.root_cause:
            lines.append("### 🔍 疑似根因")
            lines.append("")
            lines.append(f"**{anomaly.root_cause.description}**")
            lines.append(f"- 类别: {anomaly.root_cause.category}")
            lines.append(f"- 置信度: {anomaly.root_cause.confidence:.0%}")
            lines.append(f"- 推理: {anomaly.root_cause.reasoning}")
            lines.append("")

        # 建议
        if anomaly.recommendations:
            lines.append("### 💡 建议")
            lines.append("")
            for rec in anomaly.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

    # 开销
    if overhead:
        lines.append("## 工具开销")
        lines.append("")
        lines.append("| 探针 | CPU% | 内存MB |")
        lines.append("|------|------|--------|")
        for probe, info in overhead.items():
            cpu = info.get("cpu_percent", 0) if isinstance(info, dict) else 0
            mem = info.get("memory_mb", 0) if isinstance(info, dict) else 0
            lines.append(f"| {probe} | {cpu} | {mem} |")
        lines.append("")

    return "\n".join(lines)


# ───────────────────── 终端表格输出 ─────────────────────

def format_table(anomalies: List[Anomaly]) -> str:
    """格式化为终端友好的表格输出"""
    if not anomalies:
        return "[✓] 系统运行正常，未检测到异常"

    lines = []
    severity_icons = {"low": "🟢", "medium": "🟡", "high": "🔴", "critical": "🚨"}
    type_names = {
        "cpu_anomaly": "CPU异常",
        "io_anomaly": "I/O异常",
        "memory_anomaly": "内存异常",
        "lock_anomaly": "锁竞争",
        "syscall_anomaly": "系统调用",
    }

    lines.append("=" * 72)
    lines.append("  eBPF Diagnoser - 异常诊断结果")
    lines.append("=" * 72)

    for i, anomaly in enumerate(anomalies, 1):
        icon = severity_icons.get(anomaly.severity.value, "⚠️")
        type_name = type_names.get(anomaly.type.value, anomaly.type.value)
        lines.append(f"\n{icon} [{i}] {type_name} (严重度: {anomaly.severity.value}, 置信度: {anomaly.confidence:.0%})")
        lines.append("-" * 72)

        # 受影响对象
        if anomaly.affected_objects:
            objs = []
            for obj in anomaly.affected_objects:
                if obj.object_type == "process":
                    objs.append(f"{obj.comm}(PID:{obj.pid})")
                elif obj.object_type == "device":
                    objs.append(obj.device or "")
                elif obj.object_type == "syscall":
                    objs.append(obj.syscall_name or "")
            if objs:
                lines.append(f"  关联对象: {', '.join(objs[:3])}")

        # 关键指标
        if anomaly.key_metrics:
            metrics_str = " | ".join(f"{k}={v}" for k, v in list(anomaly.key_metrics.items())[:4])
            lines.append(f"  关键指标: {metrics_str}")

        # 根因
        if anomaly.root_cause:
            lines.append(f"  疑似根因: {anomaly.root_cause.description}")
            lines.append(f"  置信度: {anomaly.root_cause.confidence:.0%}")

        # 证据链 (简略)
        if anomaly.evidence_chain:
            for step in anomaly.evidence_chain[:2]:
                lines.append(f"    → {step.description}: {step.value}")

        # 建议 (简略)
        if anomaly.recommendations:
            lines.append(f"  建议: {anomaly.recommendations[0]}")

    lines.append("\n" + "=" * 72)
    return "\n".join(lines)


class OutputFormatter:
    """输出格式化器"""

    def __init__(self, format_type: str = "table"):
        self.format_type = format_type

    def format_anomalies(self, anomalies: List[Anomaly]) -> str:
        """格式化异常列表"""
        if self.format_type == "json":
            return format_json(anomalies)
        elif self.format_type == "yaml":
            return format_yaml(anomalies)
        elif self.format_type == "md":
            return format_markdown(anomalies)
        else:
            return format_table(anomalies)

    def format_report(self, anomalies: List[Anomaly], system_info: dict = None,
                      duration: float = 0, overhead: dict = None) -> Dict[str, str]:
        """格式化完整报告(含系统信息和开销)"""
        return {
            "json": format_json(anomalies, system_info, duration, overhead),
            "yaml": format_yaml(anomalies, system_info, duration, overhead),
            "md": format_markdown(anomalies, system_info, duration, overhead),
            "table": format_table(anomalies),
        }