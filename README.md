# eBPF Diagnoser

> 基于eBPF的轻量级系统异常观测与根因定位工具

## 概述

eBPF Diagnoser 是一个基于 eBPF 技术的 Linux 系统异常实时观测与根因定位工具，能够以低侵入、低开销的方式动态跟踪内核与用户态行为，支持5类典型异常场景的自动检测、指标采集、事件关联分析和诊断结果输出。

## 支持的异常场景

| 场景 | 检测能力 | 根因定位 |
|------|---------|---------|
| CPU异常占用 | CPU使用率、上下文切换、调度延迟 | CPU密集计算/线程竞争/busy loop |
| I/O延迟抖动 | IOPS、P99时延、队列深度、热点设备 | 队列过深/缓存失效/热点文件 |
| 内存抖动/OOM | 内存使用率、page fault、kswapd活跃度 | 进程泄漏/系统内存不足/OOM风险 |
| 锁竞争 | futex等待时间、争用率、热点调用栈 | 临界区过大/锁粒度过粗 |
| 系统调用异常 | syscall频率、耗时分布、慢syscall | 轮询/阻塞型调用/错误率高 |

## 快速开始

### 环境要求

- Linux 内核 6.6+ (推荐 openKylin / Ubuntu 24.04)
- Python 3.9+
- BCC (BPF Compiler Collection)
- root 权限 (或 CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN)

### 安装 (Ubuntu 24.04)

```bash
# 安装eBPF依赖
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
    bpfcc-tools python3-bpfcc libbpfcc-dev bpftool

# 安装Python依赖
pip install pyyaml rich

# 克隆项目
git clone https://github.com/yourname/ebpf-diagnoser.git
cd ebpf-diagnoser
```

### 环境搭建 (Windows QEMU + openKylin)

> 详细步骤请参考 [openKylin环境搭建指南](docs/openKylin环境搭建指南.md)

```powershell
# 1. 安装QEMU并下载openKylin ISO，创建VM磁盘
.\scripts\install-openkylin-vm.ps1

# 2. 在QEMU窗口中完成openKylin安装后，配置eBPF开发环境
.\scripts\install-openkylin-vm.ps1 -PostInstall

# 3. SSH进入VM
ssh -p 2222 user@localhost

# 4. 在VM内传输并运行诊断工具
scp -rP 2222 . user@localhost:~/ebpf-diagnoser/
cd ~/ebpf-diagnoser
sudo python3 -m src.main --probe all
```

### 环境搭建 (openKylin 直装)

```bash
# 在openKylin系统内直接运行环境搭建脚本
sudo bash scripts/setup_env.sh

# 或手动安装依赖
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
    bpfcc-tools python3-bpfcc libbpfcc-dev bpftool
pip install pyyaml rich
```

### 使用方式

```bash
# 启动所有探针 (默认终端表格输出)
sudo python3 -m src.main

# 只加载指定探针
sudo python3 -m src.main --probe cpu,io,mem

# JSON格式输出
sudo python3 -m src.main --output json

# Markdown诊断报告
sudo python3 -m src.main --output md --output-file report.md

# 运行指定时长后退出
sudo python3 -m src.main --duration 60

# 自定义阈值
sudo python3 -m src.main --threshold cpu_usage_high=80,io_p99_high=30

# 详细输出
sudo python3 -m src.main -v
```

### 压测验证

```bash
# CPU压测 + 诊断
sudo bash scripts/stress_cpu.sh &
sudo python3 -m src.main --probe cpu --duration 60

# 全场景组合压测
sudo bash scripts/stress_composite.sh &
sudo python3 -m src.main --probe all --duration 120 --output all

# 一键测试 (5类场景自动验证)
sudo bash scripts/run_tests.sh

# 性能开销基准测试
sudo bash scripts/benchmark_overhead.sh
```

## 项目结构

```
ebpf-diagnoser/
├── src/
│   ├── main.py              # CLI入口
│   ├── config.py            # 配置管理
│   ├── probes/              # eBPF探针
│   │   ├── base.py          # 探针基类
│   │   ├── cpu_probe.py     # CPU探针
│   │   ├── io_probe.py      # I/O探针
│   │   ├── mem_probe.py     # 内存探针
│   │   ├── lock_probe.py    # 锁探针
│   │   └── syscall_probe.py # 系统调用探针
│   ├── collector/           # 指标聚合
│   │   └── aggregator.py    # 滑动窗口+动态基线
│   ├── analyzer/            # 根因分析
│   │   ├── anomaly.py       # 异常数据模型
│   │   ├── rules.py         # 规则引擎
│   │   └── engine.py        # 分析引擎+关联分析
│   └── output/              # 结构化输出
│       └── formatter.py     # JSON/Markdown/终端表格
├── config/
│   └── default.yaml         # 默认配置
├── rules/
│   └── cpu_rules.yaml       # 自定义规则示例
├── scripts/
│   ├── install-openkylin-vm.ps1   # Windows QEMU VM安装脚本
│   ├── postinstall-openkylin-win.sh # VM内eBPF环境配置
│   ├── start-vm.ps1               # 快速启动VM
│   ├── ssh-to-vm.ps1              # SSH连接VM
│   ├── setup_env.sh               # 环境搭建(Linux内运行)
│   ├── stress_cpu.sh              # CPU压测
│   ├── stress_io.sh               # I/O压测
│   ├── stress_mem.sh              # 内存压测
│   ├── stress_lock.sh             # 锁竞争压测
│   ├── stress_syscall.sh          # 系统调用压测
│   ├── stress_composite.sh        # 组合压测
│   ├── run_tests.sh               # 一键测试
│   └── benchmark_overhead.sh      # 性能开销测试
├── docker/
│   └── openkylin-test.Dockerfile   # 兼容性测试Dockerfile
├── docs/                    # 文档
├── tests/                   # 测试
├── pyproject.toml
└── README.md
```

## 输出示例

### JSON格式

```json
{
  "version": "1.0",
  "timestamp": "2026-07-01T14:30:25+08:00",
  "diagnosis_id": "diag-20260701-143025-001",
  "anomalies": [{
    "type": "cpu_anomaly",
    "severity": "high",
    "confidence": 0.92,
    "time_window": { "start": "2026-07-01T14:30:20", "end": "2026-07-01T14:30:25" },
    "affected_objects": [{ "object_type": "process", "pid": 12345, "comm": "stress-ng-cpu" }],
    "key_metrics": { "cpu_usage_percent": 92.3, "ctx_switch_per_min": 32000 },
    "evidence_chain": [
      { "step": 1, "description": "CPU使用率持续高于90%", "metric": "cpu.global.cpu_usage_percent", "value": 92.3 },
      { "step": 2, "description": "上下文切换率异常升高", "metric": "cpu.global.context_switches_per_sec", "value": 533 }
    ],
    "root_cause": {
      "description": "用户态计算热点导致CPU饱和",
      "category": "cpu_intensive_compute",
      "confidence": 0.85
    },
    "recommendations": ["检查高CPU占用进程", "使用perf record定位热点函数"]
  }]
}
```

### 终端表格

```
======================================================================
  eBPF Diagnoser - 异常诊断结果
======================================================================

🔴 [1] CPU异常 (严重度: high, 置信度: 85%)
----------------------------------------------------------------------
  关联对象: stress-ng-cpu(PID:12345)
  关键指标: cpu_usage_percent=92.3 | ctx_switch_per_min=32000
  疑似根因: 用户态计算热点导致CPU饱和
  置信度: 85%
    → CPU使用率持续高于90%: 92.3
    → 上下文切换率异常升高: 533
  建议: 检查高CPU占用进程是否为预期业务

======================================================================
```

## 性能开销目标

| 指标 | 目标 |
|------|------|
| CPU开销 | < 2% 单核 |
| 内存开销 | < 100MB |
| I/O P99时延影响 | < 5% |
| 系统吞吐下降 | < 3% |

## 许可证

Apache License 2.0