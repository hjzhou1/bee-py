#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deps.py — 外部工具依赖管理器
每个攻击工具调用前先 check → 没装就问要不要装 → 装了就用 → 没装就降级到自研逻辑

原则：双管齐下。有成熟开源项目就对接，没有就从 dict 文件兜底。
"""

import os, sys, subprocess, shutil, json, requests, tempfile, zipfile, io

DEPS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools_ext")
os.makedirs(DEPS_DIR, exist_ok=True)

# ==================== 颜色 ====================
class C:
    G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'
    B = '\033[94m'; RS = '\033[0m'; BD = '\033[1m'

# ==================== 依赖定义 ====================
DEPENDENCIES = {
    # === 字典类（下载到 dict/） ===
    "seclists_admin": {
        "name": "SecLists 管理员路径字典",
        "type": "dict",
        "desc": "seclists/Discovery/Web-Content 包含50000+条路径",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
        "install": "auto_download_dict",
        "dict_key": "web_paths_large",
        "dict_file": "web_paths_large.txt",
    },
    "seclists_common": {
        "name": "SecLists 通用路径字典",
        "type": "dict",
        "desc": "seclists/Discovery/Web-Content/common.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "install": "auto_download_dict",
        "dict_key": "web_paths_common",
        "dict_file": "web_paths_common.txt",
    },
    "lfi_payloads": {
        "name": "LFI 攻击载荷字典",
        "type": "dict",
        "desc": "PayloadsAllTheThings Directory Traversal payloads",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory_traversal.txt",
        "install": "auto_download_dict",
        "dict_key": "lfi_payloads",
        "dict_file": "lfi_payloads.txt",
    },

    # === 可执行工具类 ===
    "sqlmap": {
        "name": "sqlmap（SQL注入检测）",
        "type": "tool",
        "desc": "业界最强的SQL注入自动化检测工具",
        "check": "which sqlmap || test -f tools_ext/sqlmap/sqlmap.py",
        "check_cmd": ["sqlmap", "--version"],
        "install_cmd": "git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git tools_ext/sqlmap",
        "run": "python tools_ext/sqlmap/sqlmap.py",
    },
    "xsstrike": {
        "name": "XSStrike（XSS检测）",
        "type": "tool",
        "desc": "高级XSS检测工具，支持反射/DOM/盲XSS",
        "check": "test -f tools_ext/XSStrike/xsstrike.py",
        "check_cmd": ["python", "tools_ext/XSStrike/xsstrike.py", "--help"],
        "install_cmd": "git clone --depth 1 https://github.com/s0md3v/XSStrike.git tools_ext/XSStrike",
        "run_prefix": ["python", "tools_ext/XSStrike/xsstrike.py"],
    },
    "ffuf": {
        "name": "ffuf（高速Web路径爆破）",
        "type": "tool",
        "desc": "Go写的超高速Web fuzzer，比Python快50倍",
        "check": "which ffuf",
        "check_cmd": ["ffuf", "-V"],
        "install_cmd": {
            "darwin": "brew install ffuf",
            "linux": "go install github.com/ffuf/ffuf/v2@latest",
            "manual": "https://github.com/ffuf/ffuf/releases",
        },
        "run": "ffuf",
    },
    "git_dumper": {
        "name": "git-dumper（Git仓库复原）",
        "type": "tool",
        "desc": "从暴露的.git目录下载完整Git仓库",
        "check": "which git-dumper || test -f tools_ext/git-dumper/git_dumper.py",
        "install_cmd": "git clone --depth 1 https://github.com/arthaud/git-dumper.git tools_ext/git-dumper",
        "run": "python tools_ext/git-dumper/git_dumper.py",
    },
}

# ==================== 核心函数 ====================

def get_dict_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dict")

def check_dep(dep_id):
    """检查依赖是否存在 → (bool, path_or_none)"""
    dep = DEPENDENCIES.get(dep_id)
    if not dep:
        return False, None

    if dep.get("type") == "dict":
        dict_dir = get_dict_dir()
        dict_file = os.path.join(dict_dir, dep["dict_file"])
        exists = os.path.exists(dict_file) and os.path.getsize(dict_file) > 1000
        return exists, dict_file if exists else None

    elif dep.get("type") == "tool":
        check = dep.get("check", "")
        if "||" in check:
            # 多条件：任一满足即可
            conds = check.split("||")
            for c in conds:
                c = c.strip()
                if c.startswith("test -f"):
                    path = c.replace("test -f", "").strip()
                    full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", path)
                    if os.path.exists(full_path):
                        return True, full_path
                elif c.startswith("which"):
                    cmd = c.replace("which", "").strip()
                    if shutil.which(cmd):
                        return True, shutil.which(cmd)
        else:
            if shutil.which(check):
                return True, shutil.which(check)
        return False, None
    return False, None

def install_dep(dep_id, auto=False):
    """安装依赖。auto=True 跳过确认直接装"""
    dep = DEPENDENCIES.get(dep_id)
    if not dep:
        print(f"{C.R}[-] 未知依赖: {dep_id}{C.RS}")
        return False

    if dep.get("type") == "dict":
        return _install_dict(dep)

    elif dep.get("type") == "tool":
        install_cmd = dep.get("install_cmd", "")
        if isinstance(install_cmd, dict):
            platform = sys.platform
            install_cmd = install_cmd.get(platform, install_cmd.get("manual", ""))

        if not install_cmd:
            print(f"{C.Y}[!] {dep['name']} 无自动安装脚本，请手动安装{C.RS}")
            print(f"    查看: {dep.get('desc','')}")
            return False

        print(f"{C.B}[INFO] 安装 {dep['name']}...{C.RS}")
        print(f"    命令: {install_cmd}")

        if not auto:
            choice = input(f"    执行安装？(y/n) [y]: ").strip().lower()
            if choice and choice != 'y':
                return False

        cwd = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        result = os.system(f"cd {cwd} && {install_cmd}")
        return result == 0
    return False

def _install_dict(dep):
    """下载字典文件到 dict/"""
    dict_dir = get_dict_dir()
    os.makedirs(dict_dir, exist_ok=True)
    dict_file = os.path.join(dict_dir, dep["dict_file"])
    url = dep.get("url", "")

    if not url:
        return False

    print(f"{C.B}[INFO] 下载字典: {dep['name']} ({dep.get('desc','')}){C.RS}")
    print(f"    从: {url}")

    try:
        resp = requests.get(url, timeout=30, stream=True)
        if resp.status_code == 200:
            with open(dict_file, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(resp.text)
            size_kb = os.path.getsize(dict_file) / 1024
            print(f"{C.G}[+] 下载完成: {dep['dict_file']} ({size_kb:.1f} KB){C.RS}")
            return True
        else:
            print(f"{C.R}[-] 下载失败: HTTP {resp.status_code}{C.RS}")
            return False
    except Exception as e:
        print(f"{C.R}[-] 下载失败: {e}{C.RS}")
        return False

def load_dict(dep_id):
    """加载字典文件，返回行列表"""
    dep = DEPENDENCIES.get(dep_id)
    if not dep:
        return []
    dict_dir = get_dict_dir()
    dict_file = os.path.join(dict_dir, dep["dict_file"])
    if not os.path.exists(dict_file):
        return []
    with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return lines

def ensure_dep(dep_id, auto=False):
    """
    保证依赖可用。优先级：
    1. 已安装 → 直接用
    2. 未安装 → 自动安装（auto=True）或询问安装
    3. 安装失败 → 返回 False，调用方降级到自研逻辑
    """
    exists, _ = check_dep(dep_id)
    if exists:
        return True

    dep = DEPENDENCIES.get(dep_id, {})
    print(f"{C.Y}[!] {dep.get('name', dep_id)} 未安装{C.RS}")
    print(f"    {dep.get('desc', '')}")

    if install_dep(dep_id, auto=auto):
        exists, _ = check_dep(dep_id)
        return exists

    return False

def run_sqlmap(url, data=None, extra_args=None):
    """调用 sqlmap 并返回结果"""
    cmd = ["sqlmap", "-u", url, "--batch", "--random-agent", "--level=1", "--risk=1"]
    if data:
        cmd.extend(["--data", data])
    if extra_args:
        cmd.extend(extra_args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout + result.stderr, result.returncode
    except:
        return "", -1

def run_xsstrike(url, params=None):
    """调用 XSStrike 并返回结果"""
    xsstrike = os.path.join(DEPS_DIR, "XSStrike", "xsstrike.py")
    if not os.path.exists(xsstrike):
        return "", -1
    cmd = ["python3", xsstrike, "-u", url, "--crawl", "1"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout, result.returncode
    except:
        return "", -1

def run_ffuf(url, wordlist_path, match_codes="200,301,302,403"):
    """调用 ffuf 做路径爆破"""
    if not shutil.which("ffuf"):
        return "", -1
    cmd = ["ffuf", "-u", url + "/FUZZ", "-w", wordlist_path,
           "-mc", match_codes, "-t", "50", "-o", "/tmp/ffuf_result.json",
           "-of", "json", "-s"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        # ffuf -s 只输出结果，不输出进度
        output = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                output.append(line.strip())
        return "\n".join(output[-100:]), result.returncode
    except:
        return "", -1
