"""ebpf-diagnoser 入口点

支持以下运行方式:
    ebpf-diagnoser <command>         # pip install后直接使用
    python -m src <command>          # 模块方式运行
"""

from src.cli import cli

if __name__ == "__main__":
    cli()
