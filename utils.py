#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
utils.py - 公共工具模块 v2.0
架构重构：核心能力已迁移到core/目录，本文件保持向后兼容导出
包含：颜色输出、文件名清洗、向后兼容包装类、CancelToken、字典更新、命令执行、工具验证
"""

import os
import re
import json
import html as html_lib
import time
import random
import threading
import urllib.parse
import subprocess
import shlex
from datetime import datetime
from typing import Optional, Dict, List, Any
from difflib import SequenceMatcher

import requests

# 从core模块导入新架构类，保持向后兼容
from core.ratelimit import AdaptiveRateLimiter, SimpleRateLimiter, RateLimitConfig, ConnectionState
from core.proxy import ProxyPool as CoreProxyPool
from core.session import create_secure_session as core_create_session

# ==================== 配置 ====================
DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 3
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]

# ==================== 颜色输出 ====================
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    # 短别名（兼容diaodu.py/lfi.py/weblogin.py的缩写引用）
    G = GREEN
    R = RED
    Y = YELLOW
    B = BLUE
    C = CYAN
    BD = BOLD
    RS = RESET

# ==================== 安全文件名清洗 ====================
def sanitize_filename(filename: str) -> str:
    """清洗文件名，防止路径遍历攻击"""
    if not filename:
        return "unknown"
    filename = os.path.basename(filename)
    filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
    if len(filename) > 100:
        name, ext = os.path.splitext(filename)
        filename = name[:95] + ext
    return filename or "unknown"

def sanitize_domain(domain: str) -> str:
    """清洗域名用于文件名"""
    return sanitize_filename(domain)

# ==================== 向后兼容：旧RateLimiter包装新AdaptiveRateLimiter ====================
class RateLimiter:
    """旧版速率限制器兼容包装器（推荐使用core.AdaptiveRateLimiter）"""
    def __init__(self, min_delay: float = 0.02, max_delay: float = 10.0, initial_delay: float = 0.15, preset: str = "normal"):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.initial_delay = initial_delay
        # 先按preset创建，保留preset的全部参数（线程数/窗口/阈值等）
        self._limiter = AdaptiveRateLimiter(preset=preset)
        # 只在用户显式指定（非默认值）时覆盖，保留preset的min_delay/max_threads等配置
        if min_delay != 0.02:
            self._limiter.config.min_delay = min_delay
        if max_delay != 10.0:
            self._limiter.config.max_delay = max_delay
        if initial_delay != 0.15:
            self._limiter.config.initial_delay = initial_delay
            self._limiter.current_delay = initial_delay
    
    def wait(self):
        self._limiter.wait()
    
    def report_success(self):
        self._limiter.record_state(ConnectionState.SUCCESS)
    
    def report_failure(self):
        self._limiter.record_state(ConnectionState.NO_RESPONSE)
    
    def report_error(self, status_code=None):
        if status_code == 429 or status_code == 503:
            self._limiter.record_state(ConnectionState.CONN_REFUSED)
        elif status_code and status_code >= 500:
            self._limiter.record_state(ConnectionState.NO_RESPONSE)
        else:
            self._limiter.record_state(ConnectionState.TIMEOUT)
    
    def get_current_delay(self):
        return self._limiter.get_current_delay()
    
    def get_optimal_threads(self):
        return self._limiter.get_optimal_threads()
    
    def get_stats(self):
        return self._limiter.get_stats()
    
    def __len__(self):
        return 1

# ==================== 向后兼容：旧ProxyPool包装 ====================
class ProxyPool(CoreProxyPool):
    """旧版代理池兼容包装器"""
    def enabled(self) -> bool:
        return len(self) > 0

# ==================== 向后兼容：create_secure_session包装 ====================
def create_secure_session(
    verify_ssl: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    proxy_pool: Optional[ProxyPool] = None,
    rate_limiter: Optional[RateLimiter] = None,
    random_ua: bool = True,
    custom_headers: Optional[Dict[str, str]] = None
) -> requests.Session:
    return core_create_session(
        verify_ssl=verify_ssl, timeout=timeout, retries=retries,
        proxy_pool=proxy_pool, rate_limiter=rate_limiter._limiter if isinstance(rate_limiter, RateLimiter) else rate_limiter,
        random_ua=random_ua, custom_headers=custom_headers
    )

# ==================== 404智能检测 ====================
def is_wildcard_404(resp, wildcard_content: str, wildcard_len: int, wildcard_title: Optional[str] = None) -> bool:
    """多级404过滤，CPU友好
    返回True表示该响应是通配符404页面
    """
    if not resp or not wildcard_content:
        return False
    
    resp_text = resp.text
    resp_len = len(resp_text)
    
    if abs(resp_len - wildcard_len) < 50:
        return True
    
    if wildcard_title:
        title_match = re.search(r"<title>(.*?)</title>", resp_text, re.I | re.S)
        resp_title = title_match.group(1).strip() if title_match else ""
        if resp_title and resp_title == wildcard_title:
            return True
    
    if resp_len < 5000 and len(wildcard_content) < 5000:
        sample_resp = resp_text[:2000]
        sample_wild = wildcard_content[:2000]
        if hash(sample_resp) == hash(sample_wild):
            return True
        ratio = SequenceMatcher(None, sample_resp, sample_wild).ratio()
        if ratio > 0.9:
            return True
    
    text_lower = resp_text[:5000].lower()
    if abs(resp_len - wildcard_len) < 200:
        if any(kw in text_lower for kw in [
            "not found", "404", "page doesn't exist", "访问的页面不存在",
            "页面不存在", "文件不存在", "资源不存在"
        ]):
            return True
    
    return False

# ==================== HTML转义 ====================
def html_escape(text: Any) -> str:
    """HTML转义，防止XSS"""
    if text is None:
        return ""
    return html_lib.escape(str(text))

# ==================== 取消信号（线程安全） ====================
class CancelToken:
    """线程安全的取消信号，用于爆破等操作中提前终止"""
    def __init__(self):
        self._event = threading.Event()
    
    def cancel(self):
        self._event.set()
    
    def is_cancelled(self) -> bool:
        return self._event.is_set()
    
    def check(self):
        """如果已取消则抛出异常"""
        if self._event.is_set():
            raise KeyboardInterrupt("操作被取消")
    
    def wait(self, timeout: Optional[float] = None):
        self._event.wait(timeout)

# ==================== 字典更新检查 ====================
DICT_UPDATE_URLS = {
    "web_paths.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt",
    "web_paths_common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    "weakpass.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    "subdomains.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
}

def check_dict_updates(dict_dir: str = "./dicts", auto_update: bool = False) -> Dict[str, Any]:
    """检查字典更新，7天自动更新周期
    返回更新状态字典
    """
    os.makedirs(dict_dir, exist_ok=True)
    results = {"checked": 0, "updated": 0, "failed": 0, "skipped": 0}
    
    version_file = os.path.join(dict_dir, ".dict_versions.json")
    versions = {}
    if os.path.exists(version_file):
        try:
            with open(version_file, 'r', encoding='utf-8') as f:
                versions = json.load(f)
        except Exception:
            pass
    
    for dict_name, url in DICT_UPDATE_URLS.items():
        results["checked"] += 1
        dict_path = os.path.join(dict_dir, dict_name)
        needs_update = False
        
        if not os.path.exists(dict_path):
            needs_update = True
        elif dict_name not in versions:
            needs_update = True
        else:
            try:
                last_update = datetime.fromisoformat(versions.get(dict_name, "2020-01-01"))
                if (datetime.now() - last_update).days >= 7:
                    needs_update = True
            except Exception:
                needs_update = True
        
        if needs_update and auto_update:
            try:
                resp = requests.get(url, timeout=30, verify=True)
                if resp.ok:
                    with open(dict_path, 'wb') as f:
                        f.write(resp.content)
                    versions[dict_name] = datetime.now().isoformat()
                    results["updated"] += 1
                else:
                    results["failed"] += 1
            except Exception:
                results["failed"] += 1
        elif needs_update:
            results["skipped"] += 1
    
    if results["updated"] > 0:
        try:
            with open(version_file, 'w', encoding='utf-8') as f:
                json.dump(versions, f, indent=2)
        except Exception:
            pass
    
    return results

# ==================== 工具白名单（已更新包含新模块） ====================
ALLOWED_TOOLS = {
    "weakpass", "weblogin", "env_leak", "git_leak", "backup_leak",
    "swagger_leak", "upload_exploit", "lfi", "sqli", "xss", "cve_version", 
    "deps", "unauth", "middleware_poc", "shiro_exploit", "springboot_exploit",
    "thinkphp_exploit", "webshell",
}

def validate_tool_id(tool_id: str) -> bool:
    """验证工具ID是否合法，防止任意模块导入"""
    if not tool_id or not isinstance(tool_id, str):
        return False
    if tool_id not in ALLOWED_TOOLS:
        return False
    if not re.match(r'^[a-z_]+$', tool_id):
        return False
    return True

# ==================== 目标URL验证 ====================
def validate_target_url(url: str) -> bool:
    """验证目标URL是否合法"""
    if not url:
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False

# ==================== 安全执行系统命令 ====================
def run_shell_command(cmd: str, cwd: Optional[str] = None, timeout: int = 300, shell: bool = False) -> subprocess.CompletedProcess:
    """安全执行shell命令，默认不使用shell防止注入"""
    if isinstance(cmd, str):
        if shell:
            args = cmd
        else:
            args = shlex.split(cmd)
    else:
        args = cmd
    
    return subprocess.run(
        args,
        cwd=cwd,
        shell=shell,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False
    )
