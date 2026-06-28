#!/usr/bin/env python3
"""ebpf-diagnoser: 向后兼容入口点

推荐使用 CLI 方式运行:
    ebpf-diagnoser run                           # 启动所有探针
    ebpf-diagnoser run --probe cpu,io            # 只加载指定探针
    ebpf-diagnoser run --output json             # 输出为JSON
    ebpf-diagnoser run --duration 60             # 运行60秒后退出
    ebpf-diagnoser status                        # 检查环境
    ebpf-diagnoser test                          # 运行测试
    ebpf-diagnoser config show                   # 查看配置

旧方式仍可用:
    sudo ebpf-diagnoser                          # 直接运行(默认run)
    sudo python -m src                           # 模块方式运行
"""

import sys
import os

def main():
    """向后兼容入口: python -m src.main 等价于 ebpf-diagnoser run"""
    from src.cli import cli

    # 如果没有传入子命令，默认使用 run
    args = sys.argv[1:]
    if not args or args[0] in ("--help", "-h", "--version"):
        # 显示帮助或版本
        cli.main(args, standalone_mode=False)
    elif args[0] not in ("run", "test", "status", "config"):
        # 旧式用法: 无子命令，直接当 run 处理
        cli.main(["run"] + args, standalone_mode=False)
    else:
        cli.main(args, standalone_mode=False)


if __name__ == "__main__":
    main()