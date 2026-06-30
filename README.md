# eBPF Diagnoser

> 基于eBPF的轻量级系统异常观测与根因定位工具

## 概述

eBPF Diagnoser 是一个基于 eBPF 技术的 Linux 系统异常实时观测与根因定位工具，支持 CPU异常、I/O延迟抖动、内存抖动/OOM、锁竞争、系统调用异常 5类场景的自动检测与诊断。

## 环境要求

- Linux 内核 6.6+ (推荐 openKylin 2.0 SP2 / Ubuntu 24.04)
- Python 3.9+
- clang 14+ (编译BPF程序)
- libbpf 1.0+ / libelf / zlib (BPF程序运行时依赖)
- root 权限 (或 CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN)

## 安装

### Ubuntu 24.04

```bash
# 安装eBPF编译和运行依赖
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
    libelf1 zlib1g pkg-config

# 安装Python依赖
pip install pyyaml rich

# 克隆项目并编译
git clone https://github.com/yourname/ebpf-diagnoser.git
cd ebpf-diagnoser
make all
pip install -e .
```

### openKylin 2.0 SP2

```bash
# 安装基础编译工具链
sudo apt install -y build-essential clang llvm llvm-dev libbpf-dev \
    linux-headers-$(uname -r) libclang-dev libpolly-17-dev pkg-config \
    libelf-dev zlib1g-dev

# 安装Python依赖
pip install pyyaml rich

# 克隆项目并编译
git clone https://github.com/yourname/ebpf-diagnoser.git
cd ebpf-diagnoser
make all
pip install -e .
```

详细环境搭建步骤请参考 [openKylin环境搭建指南](docs/openKylin环境搭建指南.md)。

## CLI 使用方式

```bash
# 启动所有探针进行诊断
sudo ebpf-diagnoser run

# 只加载指定探针
sudo ebpf-diagnoser run --probe cpu,io,mem

# JSON格式输出
sudo ebpf-diagnoser run --output json

# YAML格式输出
sudo ebpf-diagnoser run --output yaml

# Markdown诊断报告
sudo ebpf-diagnoser run --output md --output-file report.md

# 运行指定时长后退出
sudo ebpf-diagnoser run --duration 60

# 自定义阈值 (多个阈值逗号分隔)
sudo ebpf-diagnoser run --threshold cpu_usage_high=80,io_p99_high=30

# 检查系统环境就绪状态
ebpf-diagnoser status

# 运行内置功能测试
sudo ebpf-diagnoser test

# 查看当前配置
ebpf-diagnoser config show
```

## LLM智能分析

安装LLM依赖后，可使用AI增强的诊断分析功能：

```bash
# 安装LLM依赖
pip install -e .[llm]

# 配置API密钥
export EBPF_DIAGNOSER_API_KEY="your-api-key"

# 生成智能分析报告
sudo ebpf-diagnoser run --duration 60 --output json
ebpf-diagnoser analyze -i diagnosis_report.json

# 生成修复建议
sudo ebpf-diagnoser run --duration 60 --output json
ebpf-diagnoser remediate -i diagnosis_report.json

# 交互式问答
ebpf-diagnoser chat -c diagnosis_report.json

# 日志智能分析
ebpf-diagnoser log-analyze -i diagnosis_report.json -l dmesg
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

## 更多文档

- [技术细节](docs/技术细节.md) - 项目结构、架构设计、输出示例、性能开销、压测验证等
- [设计说明](docs/设计说明.md) - 架构设计文档
- [测试报告](docs/测试报告.md) - 测试报告
- [openKylin环境搭建指南](docs/openKylin环境搭建指南.md) - openKylin环境详细搭建步骤

## 许可证

Apache License 2.0
