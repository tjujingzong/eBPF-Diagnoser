# ebpf-diagnoser: 基于eBPF的系统异常观测与根因定位工具
"""
核心模块:
  - probes/     : eBPF探针定义(BCC C代码 + Python加载器)
  - collector/  : 指标采集与聚合(滑动窗口)
  - analyzer/   : 异常检测 + 根因分析引擎
  - output/     : 结构化输出(JSON/Markdown/终端表格)
"""
