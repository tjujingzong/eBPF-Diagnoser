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

- Linux 内核 6.6+ (推荐 openKylin 2.0 SP2 / Ubuntu 24.04)
- Python 3.9+
- clang 14+ (编译BPF程序)
- libbpf 1.0+ / libelf / zlib (BPF程序加载运行时依赖)
- root 权限 (或 CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN)

> **技术方案说明**: 本项目采用 **libbpf + CO-RE** (Compile Once, Run Everywhere) 方案，
> 通过C语言编写BPF探针程序，使用libbpf加载器加载预编译的BPF .o文件，
> Python端通过JSON协议与C loader进程通信，实现低开销的eBPF数据采集。
> **不依赖BCC**，避免了BCC运行时编译和LLVM依赖链的复杂性。

### 安装 (Ubuntu 24.04)

```bash
# 安装eBPF编译和运行依赖
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
    libelf1 zlib1g pkg-config

# 安装Python依赖
pip install pyyaml rich

# 克隆项目
git clone https://github.com/yourname/ebpf-diagnoser.git
cd ebpf-diagnoser

# 编译BPF探针和加载器
make all
```

### 安装 (openKylin 2.0 SP2)

```bash
# 安装基础编译工具链
sudo apt install -y build-essential clang llvm llvm-dev libbpf-dev \
    linux-headers-$(uname -r) libclang-dev libpolly-17-dev pkg-config \
    libelf-dev zlib1g-dev

# 安装Python依赖
pip install pyyaml rich

# 压测工具 (用于测试验证)
sudo apt install -y fio stress-ng

# 克隆项目并编译
git clone https://github.com/yourname/ebpf-diagnoser.git
cd ebpf-diagnoser
make all
```

详细环境搭建步骤请参考 [openKylin环境搭建指南](docs/openKylin环境搭建指南.md)。

### 一键部署

```bash
# 在openKylin内运行环境搭建脚本 (自动安装所有依赖)
sudo bash scripts/setup_env.sh

# 编译项目
make all
```

### 使用方式

```bash
# 启动所有探针 (默认终端表格输出)
sudo python3 -m src.main

# 只加载指定探针
sudo python3 -m src.main --probe cpu,io,mem

# JSON格式输出
sudo python3 -m src.main --output json

# YAML格式输出
sudo python3 -m src.main --output yaml

# Markdown诊断报告
sudo python3 -m src.main --output md --output-file report.md

# 运行指定时长后退出
sudo python3 -m src.main --duration 60

# 自定义阈值 (多个阈值逗号分隔)
sudo python3 -m src.main --threshold cpu_usage_high=80,io_p99_high=30

# 详细输出模式 (显示采集指标详情)
sudo python3 -m src.main -v
```

### 命令行参数说明

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--probe` | `-p` | 加载的探针(cpu,io,mem,lock,syscall,all) | all |
| `--output` | `-o` | 输出格式(json,yaml,md,table,all) | table |
| `--output-file` | `-f` | 输出文件路径 | stdout |
| `--duration` | `-d` | 运行时长(秒)，0=持续运行 | 0 |
| `--interval` | `-i` | 指标采集间隔(秒) | 1.0 |
| `--config` | `-c` | 自定义配置文件路径(YAML) | 内置默认 |
| `--threshold` | | 阈值覆盖(key=value,...) | 无 |
| `--verbose` | `-v` | 详细输出模式 | false |

### 压测验证

```bash
# CPU压测 + 诊断
bash scripts/stress_cpu.sh &
sudo python3 -m src.main --probe cpu --duration 60

# 全场景组合压测
bash scripts/stress_composite.sh &
sudo python3 -m src.main --probe all --duration 120 --output all

# 一键测试 (7项自动验证，含5类异常场景+JSON格式+多探针协同)
sudo bash scripts/run_tests.sh

# 性能开销基准测试
sudo bash scripts/benchmark_overhead.sh
```

## 项目结构

```
ebpf-diagnoser/
├── bpf/                         # BPF探针C源码
│   ├── common/                  # BPF公共头文件
│   │   ├── vmlinux.h            # 内核类型定义(BTF生成)
│   │   └── vmlinux_types.h      # 精简版内核类型
│   ├── loader/
│   │   └── bpf_loader.c         # C BPF加载器(libbpf JSON协议)
│   ├── cpu_probe.bpf.c          # CPU探针(sched tracepoint)
│   ├── io_probe.bpf.c           # I/O探针(block tracepoint)
│   ├── mem_probe.bpf.c          # 内存探针(vmscan tracepoint)
│   ├── lock_probe.bpf.c         # 锁探针(futex tracepoint)
│   └── syscall_probe.bpf.c      # 系统调用探针(raw_syscalls)
├── src/
│   ├── main.py                  # CLI入口
│   ├── config.py                # 配置管理(三层优先级)
│   ├── probes/                  # eBPF探针Python封装
│   │   ├── base.py              # 探针基类
│   │   ├── bpf_loader.py        # C loader进程管理
│   │   ├── cpu_probe.py         # CPU探针
│   │   ├── io_probe.py          # I/O探针
│   │   ├── mem_probe.py         # 内存探针
│   │   ├── lock_probe.py        # 锁探针
│   │   └── syscall_probe.py     # 系统调用探针
│   ├── collector/               # 指标采集
│   │   └── aggregator.py        # 滑动窗口+动态基线(3-sigma)
│   ├── analyzer/                # 异常检测与根因分析
│   │   ├── anomaly.py           # 异常数据模型
│   │   ├── rules.py             # 规则引擎(动态阈值)
│   │   └── engine.py            # 分析引擎+跨场景关联
│   └── output/
│       └── formatter.py         # JSON/YAML/Markdown/终端表格
├── config/
│   └── default.yaml             # 默认配置(阈值+探针+输出)
├── rules/
│   └── cpu_rules.yaml           # 自定义规则示例
├── scripts/
│   ├── setup_env.sh             # 环境搭建(Linux内运行)
│   ├── run_tests.sh             # 一键测试(7项自动验证)
│   ├── benchmark_overhead.sh    # 性能开销基准测试
│   ├── stress_cpu.sh            # CPU压测
│   ├── stress_io.sh             # I/O压测
│   ├── stress_mem.sh            # 内存压测
│   ├── stress_lock.sh           # 锁竞争压测
│   ├── stress_syscall.sh        # 系统调用压测
│   ├── stress_composite.sh      # 组合压测
│   ├── build_installer.sh       # 打包安装脚本
│   └── postinstall-openkylin.sh # openKylin安装后配置
├── docs/
│   ├── 设计说明.md               # 架构设计文档
│   ├── 测试报告.md               # 测试报告+环境搭建
│   ├── openKylin环境搭建指南.md  # openKylin环境详细指南
│   └── 题目要求.md               # 竞赛题目要求
├── docker/
│   └── openkylin-test.Dockerfile # 容器化测试
├── Makefile                     # 编译脚本(BPF+loader)
├── pyproject.toml               # Python包配置
└── README.md
```

## 架构设计

详细架构设计请参见 [设计说明](docs/设计说明.md)。

核心架构分为四层：
1. **BPF探针层** (C语言): 5个独立BPF程序，通过tracepoint挂载到内核，零拷贝采集指标
2. **加载器层** (C bpf_loader): 长驻进程，通过stdin/stdout JSON协议提供BPF程序加载、挂载和map读取
3. **分析层** (Python): 指标聚合(滑动窗口+动态基线) + 规则引擎(可配阈值) + 跨场景关联分析
4. **输出层** (Python): JSON/YAML/Markdown/终端表格四种格式

## 限制说明

- 需要root权限或CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN能力
- 当前仅支持x86_64架构(ARM64可通过修改BPF头文件支持)
- BPF探针使用tracepoint挂载，依赖内核调度/块设备/内存管理等子系统的tracepoint接口
- 动态基线需要30个样本的预热期，前30秒采集使用静态阈值
- 系统调用探针在全采样模式下(sample_rate=1)对高频syscall场景有一定开销，建议生产环境设置采样率>1
- 异常抑制窗口为30秒，同类异常在30秒内不重复报告

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