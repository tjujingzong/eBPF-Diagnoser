"""异常数据模型

定义异常事件、严重程度、异常类型等数据结构
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


class AnomalyType(str, Enum):
    """异常类型"""
    CPU_ANOMALY = "cpu_anomaly"
    IO_ANOMALY = "io_anomaly"
    MEMORY_ANOMALY = "memory_anomaly"
    LOCK_ANOMALY = "lock_anomaly"
    SYSCALL_ANOMALY = "syscall_anomaly"


class Severity(str, Enum):
    """严重程度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class EvidenceStep:
    """证据链中的一步"""
    step: int                                    # 步骤序号
    description: str                              # 描述
    metric: str                                   # 指标名
    value: Any                                    # 当前值
    baseline: Optional[float] = None              # 基线值
    timestamp: Optional[str] = None               # 时间戳

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "description": self.description,
            "metric": self.metric,
            "value": self.value,
            "baseline": self.baseline,
            "timestamp": self.timestamp,
        }


@dataclass
class AffectedObject:
    """受影响的对象(进程/线程/设备/文件)"""
    object_type: str                              # process, thread, device, file, lock, syscall
    pid: Optional[int] = None
    tid: Optional[int] = None
    comm: Optional[str] = None
    device: Optional[str] = None
    filepath: Optional[str] = None
    lock_addr: Optional[str] = None
    syscall_name: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"object_type": self.object_type}
        if self.pid is not None:
            d["pid"] = self.pid
        if self.tid is not None:
            d["tid"] = self.tid
        if self.comm is not None:
            d["comm"] = self.comm
        if self.device is not None:
            d["device"] = self.device
        if self.filepath is not None:
            d["filepath"] = self.filepath
        if self.lock_addr is not None:
            d["lock_addr"] = self.lock_addr
        if self.syscall_name is not None:
            d["syscall_name"] = self.syscall_name
        return d


@dataclass
class RootCause:
    """疑似根因"""
    description: str                              # 根因描述
    category: str                                 # 根因类别
    confidence: float                             # 置信度(0-1)
    reasoning: str                                # 推理过程

    def to_dict(self) -> dict:
        return {
            "description": self.description,
            "category": self.category,
            "confidence": round(self.confidence, 2),
            "reasoning": self.reasoning,
        }


@dataclass
class Anomaly:
    """异常事件"""
    type: AnomalyType                             # 异常类型
    severity: Severity                            # 严重程度
    confidence: float                             # 检测置信度(0-1)
    time_window: Dict[str, str]                   # 异常时间段
    affected_objects: List[AffectedObject]         # 受影响对象
    key_metrics: Dict[str, Any]                   # 关键指标
    evidence_chain: List[EvidenceStep]            # 证据链
    root_cause: Optional[RootCause] = None        # 疑似根因
    recommendations: List[str] = field(default_factory=list)  # 建议措施

    def to_dict(self) -> dict:
        result = {
            "type": self.type.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 2),
            "time_window": self.time_window,
            "affected_objects": [obj.to_dict() for obj in self.affected_objects],
            "key_metrics": self.key_metrics,
            "evidence_chain": [step.to_dict() for step in self.evidence_chain],
            "root_cause": self.root_cause.to_dict() if self.root_cause else None,
            "recommendations": self.recommendations,
        }
        return result