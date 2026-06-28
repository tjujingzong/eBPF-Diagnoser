"""BPF加载器Python封装

管理与C bpf_loader进程的通信，通过stdin/stdout JSON协议
加载BPF程序、挂载tracepoint、读取map数据
"""

import json
import os
import subprocess
import threading
import logging
from subprocess import PIPE

logger = logging.getLogger(__name__)


class BpfLoader:
    """BPF加载器单例，管理C loader子进程"""

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        if cls._instance:
            cls._instance.shutdown()
            cls._instance = None

    def __init__(self):
        loader_path = self._find_loader_binary()
        self._proc = subprocess.Popen(
            [loader_path],
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
            text=True,
            bufsize=1,
        )
        self._next_id = 0
        self._send_lock = threading.Lock()
        logger.debug("bpf_loader started: pid=%d, path=%s", self._proc.pid, loader_path)

    def _find_loader_binary(self) -> str:
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "..", "build", "bin", "bpf_loader"),
            os.path.join(os.path.dirname(__file__), "..", "..", "bin", "bpf_loader"),
            "/opt/ebpf-diagnoser/bin/bpf_loader",
            "/usr/local/bin/bpf_loader",
        ]
        for path in candidates:
            path = os.path.normpath(path)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        raise FileNotFoundError(
            "bpf_loader 二进制未找到。请先运行 'make loader' 编译，"
            "或确认已安装到 /opt/ebpf-diagnoser/bin/"
        )

    def send(self, msg: dict) -> dict:
        with self._send_lock:
            self._next_id += 1
            msg["id"] = self._next_id
            line = json.dumps(msg) + "\n"
            try:
                self._proc.stdin.write(line)
                self._proc.stdin.flush()
                response_line = self._proc.stdout.readline()
                if not response_line:
                    stderr_output = self._proc.stderr.read(4096) if self._proc.stderr else ""
                    raise RuntimeError(f"bpf_loader 进程意外退出。stderr: {stderr_output}")
                return json.loads(response_line)
            except (BrokenPipeError, json.JSONDecodeError) as e:
                stderr_output = ""
                try:
                    stderr_output = self._proc.stderr.read(4096)
                except Exception:
                    pass
                raise RuntimeError(f"bpf_loader 通信失败: {e}。stderr: {stderr_output}")

    def shutdown(self):
        if self._proc and self._proc.poll() is None:
            try:
                self.send({"cmd": "QUIT"})
            except Exception:
                pass
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        BpfLoader._instance = None
        logger.debug("bpf_loader shutdown complete")

    def __del__(self):
        try:
            if self._proc and self._proc.poll() is None:
                self._proc.kill()
                self._proc.wait()
        except Exception:
            pass
