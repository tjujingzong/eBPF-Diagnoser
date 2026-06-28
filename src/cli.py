#!/usr/bin/env python3
"""ebpf-diagnoser CLI: 基于eBPF的轻量级系统异常观测与根因定位工具

Usage:
    sudo ebpf-diagnoser run                          # 启动所有探针进行诊断
    sudo ebpf-diagnoser run --probe cpu,io           # 只加载指定探针
    sudo ebpf-diagnoser run --duration 60            # 运行60秒后退出
    sudo ebpf-diagnoser run --output json            # 输出为JSON
    ebpf-diagnoser status                            # 检查系统环境就绪状态
    ebpf-diagnoser test                              # 运行内置功能测试
    ebpf-diagnoser config show                       # 显示当前配置
    ebpf-diagnoser config init                       # 初始化默认配置到用户目录
"""

import os
import sys
import signal
import time
import json
import logging
import platform
import subprocess
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
logger = logging.getLogger("ebpf-diagnoser")

PROBE_CHOICES = ["cpu", "io", "mem", "lock", "syscall"]
OUTPUT_CHOICES = ["json", "yaml", "table", "md", "all"]


# ═══════════════════════════════════════════════════════════════════
#  CLI Group
# ═══════════════════════════════════════════════════════════════════


@click.group()
@click.version_option(package_name="ebpf-diagnoser")
@click.option("--verbose", "-v", is_flag=True, help="详细输出模式")
@click.pass_context
def cli(ctx, verbose):
    """eBPF Diagnoser - 基于eBPF的轻量级系统异常观测与根因定位工具

    基于eBPF的系统级非侵入式异常观测与根因定位工具，支持CPU、I/O、内存、锁、系统调用五类异常的实时检测与根因分析。
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


def _setup_logging(verbose: bool):
    """配置日志"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ═══════════════════════════════════════════════════════════════════
#  ebpf-diagnoser run
# ═══════════════════════════════════════════════════════════════════


@cli.command()
@click.option(
    "--probe",
    "-p",
    type=str,
    default="all",
    help="指定加载的探针，逗号分隔。可选: cpu,io,mem,lock,syscall,all",
    show_default=True,
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(OUTPUT_CHOICES),
    default="table",
    help="输出格式",
    show_default=True,
)
@click.option(
    "--output-file",
    "-f",
    type=str,
    default=None,
    help="输出文件路径 (默认: stdout)",
)
@click.option(
    "--duration",
    "-d",
    type=int,
    default=0,
    help="运行时长(秒)，0=持续运行",
    show_default=True,
)
@click.option(
    "--interval",
    "-i",
    type=float,
    default=1.0,
    help="指标采集间隔(秒)",
    show_default=True,
)
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="自定义配置文件路径 (YAML格式)",
)
@click.option(
    "--threshold",
    type=str,
    default=None,
    help="阈值覆盖，格式: key=value,key2=value2",
)
@click.pass_context
def run(ctx, probe, output, output_file, duration, interval, config_path, threshold):
    """启动eBPF探针进行系统异常诊断

    以root权限加载eBPF探针，实时采集系统指标，检测异常并输出诊断报告。
    按 Ctrl+C 停止并生成最终报告。

    \b
    示例:
      sudo ebpf-diagnoser run                        # 全探针诊断
      sudo ebpf-diagnoser run -p cpu,io -d 60       # CPU+IO探针，运行60秒
      sudo ebpf-diagnoser run -o json -d 30         # JSON输出，30秒
      sudo ebpf-diagnoser run --threshold cpu_usage_high=80  # 覆盖阈值
    """
    # 权限检查
    if os.geteuid() != 0:
        console.print("[bold red]错误: 此命令需要root权限运行[/bold red]")
        console.print("请使用: [bold]sudo ebpf-diagnoser run[/bold]")
        sys.exit(1)

    # 延迟导入，避免status/test命令也需要BPF依赖
    from src.config import load_config
    from src.probes import ProbeManager
    from src.collector import MetricsAggregator
    from src.analyzer import AnalyzerEngine
    from src.output import OutputFormatter
    from src.probes.bpf_loader import BpfLoader

    # 加载配置
    config = load_config(config_path)

    # 应用阈值覆盖
    if threshold:
        for item in threshold.split(","):
            key, value = item.split("=", 1)
            config.set_threshold(key.strip(), float(value.strip()))

    # 解析探针列表
    if probe == "all":
        probe_names = list(PROBE_CHOICES)
    else:
        probe_names = [p.strip() for p in probe.split(",")]
        for name in probe_names:
            if name not in PROBE_CHOICES:
                console.print(f"[bold red]未知探针: {name}[/bold red]")
                console.print(f"可选探针: {', '.join(PROBE_CHOICES)}")
                sys.exit(1)

    # 打印启动信息
    _print_banner(probe_names, output, interval, duration)

    # 初始化组件
    try:
        probe_manager = ProbeManager(probe_names, config)
        aggregator = MetricsAggregator(window_size=60, interval=interval)
        analyzer = AnalyzerEngine(config)
        formatter = OutputFormatter(format_type=output)
    except Exception as e:
        console.print(f"[bold red]初始化失败: {e}[/bold red]")
        sys.exit(1)

    # 优雅退出
    running = True

    def signal_handler(sig, frame):
        nonlocal running
        console.print("\n[yellow]收到退出信号，正在停止...[/yellow]")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # 加载eBPF探针
    try:
        with console.status("[bold green]加载eBPF探针..."):
            probe_manager.attach_all()
    except Exception as e:
        console.print(f"[bold red]探针加载失败: {e}[/bold red]")
        console.print("请确认:")
        console.print("  1) 使用sudo运行")
        console.print("  2) 内核支持eBPF (Linux >= 5.2)")
        console.print("  3) 已安装eBPF运行时 (libbpf)")
        console.print("  4) BPF程序已编译 (make bpf)")
        sys.exit(1)

    console.print("[bold green]所有探针加载成功，开始采集...[/bold green]\n")

    # 主循环
    start_time = time.time()
    diagnosis_results = []
    cycle = 0

    try:
        while running:
            # 检查运行时长
            if duration > 0 and (time.time() - start_time) >= duration:
                console.print(f"\n[yellow]运行{duration}秒，自动退出[/yellow]")
                break

            cycle += 1

            # 采集指标
            metrics = probe_manager.poll_metrics()
            if not metrics:
                time.sleep(interval)
                continue

            if ctx.obj["verbose"]:
                logger.debug(
                    "metrics keys: %s",
                    {
                        k: list(v.keys()) if isinstance(v, dict) else type(v).__name__
                        for k, v in metrics.items()
                    },
                )

            # 聚合指标
            aggregator.update(metrics)

            # 异常检测 + 根因分析
            anomalies = analyzer.analyze(aggregator.get_current_snapshot())
            if anomalies:
                for anomaly in anomalies:
                    console.print(
                        f"  [bold yellow]检测到异常:[/bold yellow] "
                        f"[{anomaly.type.value}] {anomaly.root_cause.description}"
                        if anomaly.root_cause
                        else f"  [bold yellow]检测到异常:[/bold yellow] [{anomaly.type.value}]"
                    )
                diagnosis_results.extend(anomalies)

                # 实时输出
                output_text = formatter.format_anomalies(anomalies)
                if output_file:
                    with open(output_file, "a") as f:
                        f.write(output_text + "\n")
                else:
                    print(output_text)

            time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]用户中断，正在生成最终报告...[/yellow]")

    finally:
        # 生成最终诊断报告
        if diagnosis_results:
            final_report = formatter.format_report(
                anomalies=diagnosis_results,
                system_info=aggregator.get_system_info(),
                duration=time.time() - start_time,
                overhead=probe_manager.get_overhead(),
            )

            saved_files = []
            if output in ("json", "all"):
                json_path = output_file or "diagnosis_report.json"
                if output == "all":
                    json_path = (
                        json_path.replace(".json", "") + ".json"
                        if output_file
                        else "diagnosis_report.json"
                    )
                with open(json_path, "w") as f:
                    f.write(final_report.get("json", ""))
                saved_files.append(json_path)

            if output in ("yaml", "all"):
                yaml_path = output_file or "diagnosis_report.yaml"
                if output == "all":
                    yaml_path = (
                        yaml_path.replace(".yaml", "") + ".yaml"
                        if output_file
                        else "diagnosis_report.yaml"
                    )
                with open(yaml_path, "w") as f:
                    f.write(final_report.get("yaml", ""))
                saved_files.append(yaml_path)

            if output in ("md", "all"):
                md_path = output_file or "diagnosis_report.md"
                if output == "all":
                    md_path = (
                        md_path.replace(".md", "") + ".md" if output_file else "diagnosis_report.md"
                    )
                with open(md_path, "w") as f:
                    f.write(final_report.get("md", ""))
                saved_files.append(md_path)

            if saved_files:
                console.print(f"\n[green]报告已保存:[/green]")
                for f in saved_files:
                    console.print(f"  -> {f}")

        # 清理eBPF探针
        probe_manager.detach_all()
        BpfLoader.reset()
        console.print("[dim]eBPF Diagnoser 已停止[/dim]")


def _print_banner(probe_names, output, interval, duration):
    """打印启动横幅"""
    banner = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
    banner.add_column("Key", style="bold")
    banner.add_column("Value")
    banner.add_row("工具", "eBPF Diagnoser v1.0.0")
    banner.add_row("探针", ", ".join(probe_names))
    banner.add_row("输出", output)
    banner.add_row("采集间隔", f"{interval}s")
    if duration > 0:
        banner.add_row("运行时长", f"{duration}s")
    else:
        banner.add_row("运行时长", "持续运行 (Ctrl+C 停止)")
    console.print(banner)
    console.print()


# ═══════════════════════════════════════════════════════════════════
#  ebpf-diagnoser status
# ═══════════════════════════════════════════════════════════════════


@cli.command()
@click.option("--verbose", "-v", is_flag=True, help="显示详细信息")
def status(verbose):
    """检查系统环境就绪状态

    验证内核版本、eBPF支持、依赖库、BPF程序编译状态等。
    """
    checks = []

    # 1. 操作系统
    os_info = platform.platform()
    is_linux = platform.system() == "Linux"
    checks.append(("操作系统", os_info, is_linux))

    # 2. 内核版本
    kernel = platform.release()
    kernel_ok = False
    if is_linux:
        try:
            major, minor = kernel.split(".")[:2]
            kernel_ok = int(major) > 5 or (int(major) == 5 and int(minor) >= 2)
        except (ValueError, IndexError):
            pass
    checks.append(("内核版本", kernel, kernel_ok))

    # 3. root权限
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    checks.append(("root权限", "是" if is_root else "否 (诊断命令需要sudo)", is_root))

    # 4. Python版本
    py_ver = platform.python_version()
    py_ok = sys.version_info >= (3, 9)
    checks.append(("Python版本", py_ver, py_ok))

    # 5. eBPF系统支持
    bpf_support = False
    if is_linux:
        bpf_support = os.path.isdir("/sys/kernel/tracing") or os.path.isdir(
            "/sys/kernel/debug/tracing"
        )
    checks.append(("eBPF/tracefs", "已挂载" if bpf_support else "未挂载", bpf_support))

    # 6. libbpf库
    libbpf_ok = False
    try:
        result = subprocess.run(
            ["ldconfig", "-p"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        libbpf_ok = "libbpf.so" in result.stdout
    except Exception:
        pass
    checks.append(("libbpf", "已安装" if libbpf_ok else "未安装", libbpf_ok))

    # 7. clang编译器
    clang_ok = False
    try:
        result = subprocess.run(
            ["clang", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        clang_ok = result.returncode == 0
    except Exception:
        pass
    checks.append(("clang", "已安装" if clang_ok else "未安装 (编译BPF需要)", clang_ok))

    # 8. BPF程序编译状态
    bpf_compiled = False
    bpf_obj_dir = os.path.join(os.path.dirname(__file__), "..", "build", "bpf")
    bpf_obj_dir = os.path.normpath(bpf_obj_dir)
    if os.path.isdir(bpf_obj_dir):
        bpf_files = [f for f in os.listdir(bpf_obj_dir) if f.endswith(".bpf.o")]
        bpf_compiled = len(bpf_files) >= 5
    checks.append(
        (
            "BPF程序",
            f"已编译 ({len(bpf_files)}个)" if bpf_compiled else "未编译 (请运行 make bpf)",
            bpf_compiled,
        )
    )

    # 9. bpf_loader
    loader_ok = False
    loader_candidates = [
        os.path.join(os.path.dirname(__file__), "..", "build", "bin", "bpf_loader"),
        "/opt/ebpf-diagnoser/bin/bpf_loader",
        "/usr/local/bin/bpf_loader",
    ]
    for path in loader_candidates:
        if os.path.isfile(os.path.normpath(path)):
            loader_ok = True
            break
    checks.append(
        ("bpf_loader", "已编译" if loader_ok else "未编译 (请运行 make loader)", loader_ok)
    )

    # 10. Python依赖
    deps_ok = True
    missing_deps = []
    for dep in ["click", "yaml", "rich"]:
        try:
            __import__(dep)
        except ImportError:
            deps_ok = False
            missing_deps.append(dep)
    dep_status = "已安装" if deps_ok else f"缺失: {', '.join(missing_deps)}"
    checks.append(("Python依赖", dep_status, deps_ok))

    # 输出结果
    table = Table(title="eBPF Diagnoser 环境检查", box=box.ROUNDED, border_style="cyan")
    table.add_column("检查项", style="bold")
    table.add_column("状态")
    table.add_column("结果", justify="center")

    all_ok = True
    for name, detail, ok in checks:
        status_icon = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(name, detail, status_icon)
        if not ok:
            all_ok = False

    console.print(table)
    console.print()

    if all_ok:
        console.print("[bold green]环境就绪！可以直接运行诊断。[/bold green]")
        console.print("运行: [bold]sudo ebpf-diagnoser run[/bold]")
    else:
        console.print("[bold yellow]部分检查未通过，请先解决以上问题。[/bold yellow]")
        _print_fix_hints(checks)


def _print_fix_hints(checks):
    """打印修复建议"""
    hints = []
    for name, detail, ok in checks:
        if not ok:
            if name == "root权限":
                hints.append("  使用: [bold]sudo ebpf-diagnoser run[/bold]")
            elif name == "clang":
                hints.append("  Ubuntu: [bold]sudo apt install clang[/bold]")
                hints.append("  Fedora: [bold]sudo dnf install clang[/bold]")
            elif name == "libbpf":
                hints.append("  Ubuntu: [bold]sudo apt install libbpf-dev libelf1 zlib1g[/bold]")
                hints.append("  Fedora: [bold]sudo dnf install libbpf elfutils-libelf zlib[/bold]")
            elif name == "BPF程序":
                hints.append("  运行: [bold]make bpf[/bold]")
            elif name == "bpf_loader":
                hints.append("  运行: [bold]make loader[/bold]")
            elif name == "Python依赖":
                hints.append("  运行: [bold]pip install -e .[/bold]")
            elif name == "eBPF/tracefs":
                hints.append(
                    "  挂载tracefs: [bold]sudo mount -t tracefs nodev /sys/kernel/tracing[/bold]"
                )

    if hints:
        console.print("\n[bold]修复建议:[/bold]")
        for hint in hints:
            console.print(hint)


# ═══════════════════════════════════════════════════════════════════
#  ebpf-diagnoser test
# ═══════════════════════════════════════════════════════════════════


@cli.command()
@click.option(
    "--probe",
    "-p",
    type=str,
    default=None,
    help="只测试指定探针 (默认: 全部)",
)
@click.option(
    "--duration",
    "-d",
    type=int,
    default=30,
    help="每项测试时长(秒)",
    show_default=True,
)
@click.option("--verbose", "-v", is_flag=True, help="显示详细输出")
def test(probe, duration, verbose):
    """运行内置功能测试

    使用stress-ng对系统施加压力，验证各类探针的异常检测能力。
    需要root权限和已安装stress-ng。

    \b
    示例:
      sudo ebpf-diagnoser test              # 测试全部探针
      sudo ebpf-diagnoser test -p cpu       # 只测试CPU探针
      sudo ebpf-diagnoser test -d 60        # 每项测试60秒
    """
    if os.geteuid() != 0:
        console.print("[bold red]错误: 测试需要root权限运行[/bold red]")
        console.print("请使用: [bold]sudo ebpf-diagnoser test[/bold]")
        sys.exit(1)

    # 检查stress-ng
    try:
        subprocess.run(["stress-ng", "--version"], capture_output=True, timeout=5)
    except FileNotFoundError:
        console.print("[bold red]错误: 未找到stress-ng[/bold red]")
        console.print("安装: [bold]sudo apt install stress-ng[/bold]")
        sys.exit(1)

    # 延迟导入
    from src.config import load_config
    from src.probes import ProbeManager
    from src.collector import MetricsAggregator
    from src.analyzer import AnalyzerEngine
    from src.output import OutputFormatter
    from src.probes.bpf_loader import BpfLoader

    config = load_config(None)

    test_cases = [
        {
            "name": "CPU异常检测",
            "probe": "cpu",
            "stress": f"stress-ng --cpu 4 --cpu-method matrixprod --timeout {duration}s",
            "keyword": "cpu_anomaly",
            "threshold": None,
        },
        {
            "name": "I/O异常检测",
            "probe": "io",
            "stress": f"fio --name=test --filename=/tmp/fio-test.img --size=1G --rw=randrw --bs=4k --iodepth=64 --numjobs=4 --runtime={duration} --time_based",
            "keyword": "io_anomaly",
            "threshold": "--threshold io_p99_high=0.3",
        },
        {
            "name": "内存异常检测",
            "probe": "mem",
            "stress": f"stress-ng --vm 4 --vm-bytes 95% --vm-keep --timeout {duration}s",
            "keyword": "memory_anomaly",
            "threshold": "--threshold mem_available_low=60",
        },
        {
            "name": "锁竞争检测",
            "probe": "lock",
            "stress": f"stress-ng --mutex 8 --timeout {duration}s",
            "keyword": "lock_anomaly",
            "threshold": None,
        },
        {
            "name": "系统调用异常检测",
            "probe": "syscall",
            "stress": f"stress-ng --pid 8 --timeout {duration}s",
            "keyword": "syscall_anomaly",
            "threshold": None,
        },
    ]

    # 如果指定了probe，只运行对应测试
    if probe:
        test_cases = [t for t in test_cases if t["probe"] in [p.strip() for p in probe.split(",")]]
        if not test_cases:
            console.print(f"[bold red]没有匹配的测试用例: {probe}[/bold red]")
            console.print(f"可选探针: {', '.join(PROBE_CHOICES)}")
            sys.exit(1)

    console.print(
        Panel(
            f"[bold]eBPF Diagnoser 功能测试[/bold]\n"
            f"测试项: {len(test_cases)}  每项时长: {duration}s",
            border_style="cyan",
        )
    )

    pass_count = 0
    fail_count = 0
    results = []

    for tc in test_cases:
        console.print(f"\n[cyan]{'=' * 60}[/cyan]")
        console.print(f"[bold yellow]测试: {tc['name']}[/bold yellow]")
        console.print(f"探针: {tc['probe']}  压测命令: {tc['stress'][:50]}...")

        # 应用阈值
        test_config = load_config(None)
        if tc["threshold"]:
            for item in tc["threshold"].split():
                if item.startswith("--threshold"):
                    continue
                if "=" in item:
                    k, v = item.split("=", 1)
                    test_config.set_threshold(k.strip(), float(v.strip()))

        try:
            probe_manager = ProbeManager([tc["probe"]], test_config)
            aggregator = MetricsAggregator(window_size=60, interval=1.0)
            analyzer = AnalyzerEngine(test_config)

            # 启动压测
            stress_proc = subprocess.Popen(
                tc["stress"],
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(3)  # 等压测起来

            # 加载探针
            probe_manager.attach_all()

            # 运行诊断
            detected = False
            start = time.time()
            while time.time() - start < duration:
                metrics = probe_manager.poll_metrics()
                if metrics:
                    aggregator.update(metrics)
                    anomalies = analyzer.analyze(aggregator.get_current_snapshot())
                    if anomalies:
                        detected = True
                        for a in anomalies:
                            console.print(f"  [green]检测到: {a.type.value}[/green]")
                        break
                time.sleep(1.0)

            # 清理
            probe_manager.detach_all()
            BpfLoader.reset()
            stress_proc.terminate()
            try:
                stress_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stress_proc.kill()

            if detected:
                console.print(f"  [bold green]PASS[/bold green]")
                results.append((tc["name"], "PASS"))
                pass_count += 1
            else:
                console.print(f"  [bold red]FAIL[/bold red]: 未检测到 '{tc['keyword']}'")
                results.append((tc["name"], "FAIL"))
                fail_count += 1

        except Exception as e:
            console.print(f"  [bold red]ERROR: {e}[/bold red]")
            results.append((tc["name"], f"ERROR: {e}"))
            fail_count += 1
            try:
                stress_proc.terminate()
            except Exception:
                pass

    # JSON输出格式测试
    console.print(f"\n[cyan]{'=' * 60}[/cyan]")
    console.print("[bold yellow]测试: JSON输出格式完整性[/bold yellow]")

    stress_proc = subprocess.Popen(
        f"stress-ng --cpu 4 --cpu-method matrixprod --timeout {duration}s",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)

    try:
        test_config = load_config(None)
        pm = ProbeManager(["cpu"], test_config)
        agg = MetricsAggregator(window_size=60, interval=1.0)
        anl = AnalyzerEngine(test_config)
        fmt = OutputFormatter(format_type="json")

        pm.attach_all()
        start = time.time()
        anomalies_collected = []
        while time.time() - start < min(duration, 20):
            metrics = pm.poll_metrics()
            if metrics:
                agg.update(metrics)
                anomalies = anl.analyze(agg.get_current_snapshot())
                anomalies_collected.extend(anomalies)
            time.sleep(1.0)

        pm.detach_all()
        BpfLoader.reset()

        json_output = fmt.format_report(
            anomalies_collected,
            agg.get_system_info(),
            time.time() - start,
            pm.get_overhead(),
        )

        # 验证必需字段
        required_fields = ["version", "timestamp", "anomalies", "system_context", "tool_metadata"]
        json_data = json.loads(json_output.get("json", "{}"))
        missing = [f for f in required_fields if f not in json_data]

        if not missing:
            console.print("  [bold green]PASS[/bold green]: 所有必需字段存在")
            results.append(("JSON输出格式", "PASS"))
            pass_count += 1
        else:
            console.print(f"  [bold red]FAIL[/bold red]: 缺少字段: {missing}")
            results.append(("JSON输出格式", "FAIL"))
            fail_count += 1

    except Exception as e:
        console.print(f"  [bold red]ERROR: {e}[/bold red]")
        results.append(("JSON输出格式", f"ERROR: {e}"))
        fail_count += 1
    finally:
        stress_proc.terminate()
        try:
            stress_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            stress_proc.kill()

    # 清理临时文件
    try:
        os.remove("/tmp/fio-test.img")
    except OSError:
        pass

    # 汇总
    console.print(f"\n[cyan]{'=' * 60}[/cyan]")
    console.print("[bold]测试结果汇总[/bold]\n")

    summary_table = Table(box=box.SIMPLE)
    summary_table.add_column("测试项", style="bold")
    summary_table.add_column("结果", justify="center")
    for name, result in results:
        style = "green" if result == "PASS" else "red"
        summary_table.add_row(name, f"[{style}]{result}[/{style}]")
    console.print(summary_table)

    console.print(
        f"\n通过: [green]{pass_count}[/green]  失败: [red]{fail_count}[/red]  总计: {pass_count + fail_count}"
    )

    if fail_count == 0:
        console.print("\n[bold green]所有测试通过！[/bold green]")
    else:
        console.print("\n[bold yellow]部分测试失败，请检查上方输出。[/bold yellow]")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════
#  ebpf-diagnoser config
# ═══════════════════════════════════════════════════════════════════


@cli.group()
def config():
    """配置管理

    查看、初始化和管理诊断工具配置。
    """
    pass


@config.command("show")
@click.option(
    "--format", "-f", "fmt", type=click.Choice(["yaml", "json"]), default="yaml", help="输出格式"
)
def config_show(fmt):
    """显示当前生效的配置"""
    from src.config import load_config, DEFAULT_CONFIG_PATHS

    cfg = load_config(None)

    # 找到实际加载的配置文件
    loaded_path = None
    for path in DEFAULT_CONFIG_PATHS:
        if os.path.exists(path):
            loaded_path = path
            break

    console.print(
        Panel(
            f"[bold]配置来源:[/bold] {loaded_path or '代码默认值'}",
            border_style="cyan",
        )
    )

    if fmt == "json":
        console.print(json.dumps(cfg.to_dict(), indent=2, ensure_ascii=False))
    else:
        import yaml

        console.print(
            yaml.dump(
                cfg.to_dict(),
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )
        )


@config.command("init")
@click.option("--force", is_flag=True, help="覆盖已有配置")
def config_init(force):
    """初始化默认配置到用户目录 (~/.ebpf-diagnoser/config.yaml)"""
    user_config_dir = os.path.expanduser("~/.ebpf-diagnoser")
    user_config_path = os.path.join(user_config_dir, "config.yaml")

    if os.path.exists(user_config_path) and not force:
        console.print(f"[yellow]配置文件已存在: {user_config_path}[/yellow]")
        console.print("使用 --force 覆盖")
        return

    # 查找项目内置的默认配置
    builtin_config = os.path.join(os.path.dirname(__file__), "..", "config", "default.yaml")
    builtin_config = os.path.normpath(builtin_config)

    if not os.path.exists(builtin_config):
        console.print("[red]错误: 未找到内置配置文件[/red]")
        sys.exit(1)

    os.makedirs(user_config_dir, exist_ok=True)

    import shutil

    shutil.copy2(builtin_config, user_config_path)

    console.print(f"[green]配置已初始化到: {user_config_path}[/green]")
    console.print("你可以编辑此文件来自定义阈值和探针配置。")


@config.command("path")
def config_path():
    """显示配置文件搜索路径"""
    from src.config import DEFAULT_CONFIG_PATHS

    console.print("[bold]配置文件搜索路径 (按优先级):[/bold]\n")
    for i, path in enumerate(DEFAULT_CONFIG_PATHS, 1):
        exists = os.path.exists(path)
        status = "[green]存在[/green]" if exists else "[dim]不存在[/dim]"
        console.print(f"  {i}. {path}  {status}")


# ═══════════════════════════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    cli()
