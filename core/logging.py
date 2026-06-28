"""
core.logging — 统一日志输出系统
全局单例，所有模块共用同一实例
"""

import datetime
import threading
from typing import Optional


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    G = GREEN
    R = RED
    Y = YELLOW
    B = BLUE
    C = CYAN
    M = MAGENTA
    BD = BOLD
    RS = RESET


class Logger:
    """统一日志器——全局唯一实例，线程安全"""

    def __init__(self):
        self._lock = threading.Lock()

    def _log(self, level: str, message: str, color: str):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        with self._lock:
            print(f"{color}[{timestamp}] [{level}] {message}{Colors.RESET}")

    def info(self, msg: str):
        self._log("INFO", msg, Colors.BLUE)

    def success(self, msg: str):
        self._log("SUCCESS", msg, Colors.GREEN)

    def warning(self, msg: str):
        self._log("WARNING", msg, Colors.YELLOW)

    def error(self, msg: str):
        self._log("ERROR", msg, Colors.RED)

    def exploit(self, msg: str):
        """利用成功专用"""
        self._log("EXPLOIT", msg, Colors.MAGENTA)

    def raw(self, msg: str):
        """原样输出，不带时间戳"""
        with self._lock:
            print(msg)

    def banner(self, msg: str):
        """加粗横幅输出"""
        with self._lock:
            print(f"{Colors.BOLD}{Colors.CYAN}{msg}{Colors.RESET}")


_logger_instance = Logger()


def get_logger() -> Logger:
    """获取全局 Logger 单例"""
    return _logger_instance
