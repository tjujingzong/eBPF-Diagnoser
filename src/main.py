#!/usr/bin/env python3
"""ebpf-diagnoser: 基于eBPF的轻量级系统异常观测与根因定位工具

Usage:
    sudo ebpf-diagnoser                          # 启动所有探针
    sudo ebpf-diagnoser --probe cpu,io,mem       # 只加载指定探针
    sudo ebpf-diagnoser --output json            # 输出为JSON
    sudo ebpf-diagnoser --output md              # 输出为Markdown报告
    sudo ebpf-diagnoser --duration 60            # 运行60秒后退出
    sudo ebpf-diagnoser --config custom.yaml     # 自定义配置
"""

import argparse
import signal
import sys
import time
import json
import logging
from datetime import datetime

from src.probes import ProbeManager
from src.collector import MetricsAggregator
from src.analyzer import AnalyzerEngine
from src.output import OutputFormatter
from src.config import load_config

logger = logging.getLogger("ebpf-diagnoser")


def setup_logging(verbose: bool = False):
    """配置日志"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        prog="ebpf-diagnoser",
        description="基于eBPF的轻量级系统异常观测与根因定位工具",
    )
    parser.add_argument(
        "--probe", "-p",
        type=str,
        default="all",
        help="指定加载的探针，逗号分隔。可选: cpu,io,mem,lock,syscall,all (默认: all)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="table",
        choices=["json", "yaml", "table", "md", "all"],
        help="输出格式: json,yaml,table,md,all (默认: table)",
    )
    parser.add_argument(
        "--output-file", "-f",
        type=str,
        default=None,
        help="输出文件路径 (默认: stdout)",
    )
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=0,
        help="运行时长(秒)，0=持续运行 (默认: 0)",
    )
    parser.add_argument(
        "--interval", "-i",
        type=float,
        default=1.0,
        help="指标采集间隔(秒) (默认: 1.0)",
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="自定义配置文件路径 (YAML格式)",
    )
    parser.add_argument(
        "--threshold",
        type=str,
        default=None,
        help="阈值覆盖，格式: key=value,key2=value2",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="详细输出模式",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ebpf-diagnoser 1.0.0",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)

    # 加载配置
    config = load_config(args.config)

    # 应用阈值覆盖
    if args.threshold:
        for item in args.threshold.split(","):
            key, value = item.split("=", 1)
            config.set_threshold(key.strip(), float(value.strip()))

    # 解析探针列表
    if args.probe == "all":
        probe_names = ["cpu", "io", "mem", "lock", "syscall"]
    else:
        probe_names = [p.strip() for p in args.probe.split(",")]

    logger.info("eBPF Diagnoser 启动")
    logger.info(f"  探针: {probe_names}")
    logger.info(f"  输出: {args.output}")
    logger.info(f"  采集间隔: {args.interval}s")

    # 初始化组件
    probe_manager = ProbeManager(probe_names, config)
    aggregator = MetricsAggregator(window_size=60, interval=args.interval)
    analyzer = AnalyzerEngine(config)
    formatter = OutputFormatter(format_type=args.output)

    # 优雅退出
    running = True

    def signal_handler(sig, frame):
        nonlocal running
        logger.info("收到退出信号，正在停止...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # 加载eBPF探针
    try:
        probe_manager.attach_all()
    except Exception as e:
        logger.error(f"探针加载失败: {e}")
        logger.error("请确认: 1) 使用sudo运行 2) 内核支持eBPF 3) 已安装BCC工具")
        sys.exit(1)

    logger.info("所有探针加载成功，开始采集...")

    # 主循环
    start_time = time.time()
    diagnosis_results = []

    try:
        while running:
            # 检查运行时长
            if args.duration > 0 and (time.time() - start_time) >= args.duration:
                logger.info(f"运行{args.duration}秒，自动退出")
                break

            # 采集指标
            metrics = probe_manager.poll_metrics()
            if not metrics:
                time.sleep(args.interval)
                continue

            # 聚合指标
            aggregator.update(metrics)

            # 异常检测 + 根因分析
            anomalies = analyzer.analyze(aggregator.get_current_snapshot())
            if anomalies:
                for anomaly in anomalies:
                    logger.info(
                        f"检测到异常: [{anomaly.type}] {anomaly.root_cause.description}"
                    )
                diagnosis_results.extend(anomalies)

                # 实时输出
                output = formatter.format_anomalies(anomalies)
                if args.output_file:
                    with open(args.output_file, "a") as f:
                        f.write(output + "\n")
                else:
                    print(output)

            time.sleep(args.interval)

    except KeyboardInterrupt:
        logger.info("用户中断，正在生成最终报告...")

    finally:
        # 生成最终诊断报告
        if diagnosis_results:
            final_report = formatter.format_report(
                anomalies=diagnosis_results,
                system_info=aggregator.get_system_info(),
                duration=time.time() - start_time,
                overhead=probe_manager.get_overhead(),
            )
            if args.output in ("json", "all"):
                json_path = args.output_file or "diagnosis_report.json"
                if args.output == "all":
                    json_path = json_path.replace(".json", "") + ".json" if args.output_file else "diagnosis_report.json"
                with open(json_path, "w") as f:
                    f.write(final_report.get("json", ""))
                logger.info(f"JSON报告已保存: {json_path}")

            if args.output in ("md", "all"):
                md_path = args.output_file or "diagnosis_report.md"
                if args.output == "all":
                    md_path = md_path.replace(".md", "") + ".md" if args.output_file else "diagnosis_report.md"
                with open(md_path, "w") as f:
                    f.write(final_report.get("md", ""))
                logger.info(f"Markdown报告已保存: {md_path}")

        # 清理eBPF探针
        probe_manager.detach_all()
        logger.info("eBPF Diagnoser 已停止")


if __name__ == "__main__":
    main()