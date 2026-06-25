"""配置管理模块

支持默认配置 + YAML配置文件覆盖 + 命令行参数覆盖
三层优先级: 命令行 > 配置文件 > 默认值
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class ThresholdConfig:
    """异常检测阈值配置"""
    # CPU
    cpu_usage_high: float = 90.0          # CPU使用率告警阈值(%)
    cpu_usage_warn: float = 70.0          # CPU使用率警告阈值(%)
    ctx_switch_high: float = 50000.0      # 上下文切换率告警(次/分钟)
    sched_delay_high: float = 50.0        # 调度延迟告警(ms)
    runqueue_high: float = 4.0            # 运行队列长度(倍CPU核数)

    # I/O
    io_p99_high: float = 50.0             # P99延迟告警(ms)
    io_queue_depth_high: float = 32.0     # 队列深度告警
    io_await_high: float = 30.0           # 平均等待时间告警(ms)

    # 内存
    mem_available_low: float = 10.0       # 可用内存告警(%)
    mem_major_fault_high: float = 100.0   # major fault率告警(次/秒)
    kswapd_active_high: float = 50.0      # kswapd活跃度告警(%)

    # 锁
    lock_wait_high: float = 10.0          # 锁等待时间告警(ms)
    lock_contention_high: float = 50.0    # 锁争用率告警(%)

    # 系统调用
    syscall_freq_high: float = 5.0        # syscall频率告警(相对基线倍数)
    syscall_slow_ms: float = 100.0        # 慢syscall告警阈值(ms)

    # 通用
    anomaly_window: int = 3               # 异常需持续的窗口数
    baseline_window: int = 30             # 基线计算窗口(秒)
    baseline_sigma: float = 3.0           # 动态基线的sigma倍数


@dataclass
class ProbeConfig:
    """探针配置"""
    # 采样率 (1/N, 0表示不采样全部采集)
    cpu_sample_rate: int = 1              # CPU探针采样率
    io_sample_rate: int = 1               # I/O探针采样率
    mem_sample_rate: int = 1              # 内存探针采样率
    lock_sample_rate: int = 10            # 锁探针采样率(高频,默认1/10)
    syscall_sample_rate: int = 1              # 系统调用采样率(全采样)

    # 栈回溯(性能开销较大)
    enable_stack_trace: bool = False       # 是否启用栈回溯
    stack_trace_limit: int = 10           # 栈帧深度限制

    # 过滤
    pid_filter: list = field(default_factory=list)   # 只追踪指定PID(空=全部)
    comm_filter: list = field(default_factory=list)   # 只追踪指定进程名


@dataclass
class OutputConfig:
    """输出配置"""
    format: str = "table"                  # 输出格式: json, table, md
    file: Optional[str] = None             # 输出文件路径
    include_evidence_chain: bool = True    # 是否包含证据链
    include_recommendations: bool = True   # 是否包含建议
    timestamp_format: str = "%Y-%m-%dT%H:%M:%S%z"  # ISO 8601


class Config:
    """全局配置"""

    def __init__(self):
        self.thresholds = ThresholdConfig()
        self.probe = ProbeConfig()
        self.output = OutputConfig()

    def set_threshold(self, key: str, value: float):
        """动态设置阈值"""
        if hasattr(self.thresholds, key):
            setattr(self.thresholds, key, value)
        else:
            raise ValueError(f"未知阈值: {key}")

    def to_dict(self) -> Dict[str, Any]:
        """导出为字典"""
        return {
            "thresholds": self.thresholds.__dict__,
            "probe": self.probe.__dict__,
            "output": self.output.__dict__,
        }


DEFAULT_CONFIG_PATHS = [
    os.path.expanduser("~/.ebpf-diagnoser/config.yaml"),
    "/etc/ebpf-diagnoser/config.yaml",
    os.path.join(os.path.dirname(__file__), "..", "config", "default.yaml"),
]


def load_config(config_path: Optional[str] = None) -> Config:
    """加载配置

    优先级: 指定路径 > 用户目录 > 系统目录 > 包内置默认 > 代码默认值
    """
    config = Config()

    # 尝试加载配置文件
    yaml_path = None
    if config_path:
        if os.path.exists(config_path):
            yaml_path = config_path
        else:
            raise FileNotFoundError(f"配置文件不存在: {config_path}")
    else:
        for path in DEFAULT_CONFIG_PATHS:
            if os.path.exists(path):
                yaml_path = path
                break

    if yaml_path:
        with open(yaml_path, "r") as f:
            yaml_config = yaml.safe_load(f) or {}

        # 合并阈值配置
        if "thresholds" in yaml_config:
            for key, value in yaml_config["thresholds"].items():
                if hasattr(config.thresholds, key):
                    setattr(config.thresholds, key, value)

        # 合并探针配置
        if "probe" in yaml_config:
            for key, value in yaml_config["probe"].items():
                if hasattr(config.probe, key):
                    setattr(config.probe, key, value)

        # 合并输出配置
        if "output" in yaml_config:
            for key, value in yaml_config["output"].items():
                if hasattr(config.output, key):
                    setattr(config.output, key, value)

    return config