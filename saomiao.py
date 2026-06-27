#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
saomiao.py - 全栈资产测绘与漏洞发现引擎
功能：子域名探测、端口扫描、路径爆破、指纹识别、漏洞验证、安全头检测
输出：标准化 JSON 报告，可直接被 ruobp.py 读取用于弱口令爆破
"""

import socket
import urllib.parse
import datetime
import sys
import json
import re
import ssl
import uuid
import signal
from difflib import SequenceMatcher   # 1.3 通配符相似度比较
from concurrent.futures import ThreadPoolExecutor
import requests
import os

# ==================== 配置区 ====================
TARGET_URL = "https://example.com"  # 目标地址（替换为实际测试目标）
THREAD_COUNT = 30
TIMEOUT = 4
VERIFY_SSL = False
OUTPUT_DIR = "./scans"  # 扫描结果统一存放目录

# 子域名配置
SUBDOMAIN_SCAN_ENABLE = True
SUBDOMAIN_DICT = [
    "www", "api", "admin", "test", "dev", "prod", "staging", "git", "jenkins",
    "k8s", "nacos", "grafana", "prometheus", "elasticsearch", "redis", "mysql",
    "console", "dashboard", "manage", "openapi", "doc", "docs", "static", "cdn",
    "mail", "smtp", "pop3", "imap", "ftp", "sftp", "backup", "db", "database"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Connection": "close",
    "Accept-Encoding": "identity"
}

# 敏感路径字典
DIR_DICTIONARY = [
    ".git/HEAD", ".git/config", ".env", ".env.local", ".env.development", ".gitignore",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "web.config", "Dockerfile", "Dockerfile.prod",
    "backup.zip", "backup.tar.gz", "backup.rar", "www.zip", "wwwroot.zip", "web.zip",
    "index.php.bak", "config.php.bak", "database.sql", "db.sql", "db_dump.sql",
    ".vscode/settings.json", ".vscode/sftp.json", ".idea/workspace.xml", ".idea/libraries.xml",
    "composer.json", "package.json", "go.mod", "pom.xml", "Cargo.toml", "requirements.txt", "Gemfile",
    "wp-admin/", "wp-login.php", "admin/", "admin/login.php", "admin/config.php",
    "login.php", "manage/", "manager/html", "console/", "dashboard/", "cgi-bin/", "virtual/",
    "phpinfo.php", "info.php", "test.php", "tz.php", "status", "server-status",
    "actuator/env", "actuator/health", "actuator", "api/v1/", "v1/api", "swagger-ui.html",
    "api/swagger-ui.html", "swagger/index.html", "v1/swagger.json", "swagger.json",
    "zabbix/", "jenkins/", "solr/", "consul/", "etcd/", "grafana/", "kibana/", "prometheus/",
    ".aws/credentials", ".azure/credentials", ".gcp/credentials",
    ".github/workflows/main.yml", ".gitlab-ci.yml", ".travis.yml", "Jenkinsfile",
    "docker-compose.yml", "docker-compose.override.yml", "daemon.json",
    "src/", "source/", "code/", "lib/", "vendor/", "node_modules/.cache/",
    "__pycache__/", "build/", "dist/", ".gradle/", ".m2/", ".npm/",
    "api-docs/", "apidoc/", "openapi.json", "openapi.yaml", "graphql/", "api/graphql", "api/health"
]

def load_path_dictionary():
    """从 dict/ 目录加载所有路径字典（内置+本地+开源），合并去重"""
    dict_dir = os.path.join(os.path.dirname(__file__), "dict")
    paths = []
    seen = set()

    # 加载顺序：内置 → web_paths.txt → web_paths_common.txt → web_paths_large.txt
    # 后续字典自动去重追加

    source_files = ["web_paths.txt", "web_paths_common.txt", "web_paths_large.txt"]

    # 1. 内置字典作基础
    for p in DIR_DICTIONARY:
        if p not in seen:
            paths.append(p)
            seen.add(p)

    # 2. 本地字典文件
    for fname in source_files:
        fpath = os.path.join(dict_dir, fname)
        if os.path.exists(fpath):
            added = 0
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line not in seen:
                        paths.append(line)
                        seen.add(line)
                        added += 1
            if added > 0:
                print(f"{Colors.CYAN}[字典] 加载 {fname}: +{added} 条{Colors.RESET}")

    # 3. 没找到任何外部字典 → 仅用内置
    if len(paths) <= len(DIR_DICTIONARY):
        return DIR_DICTIONARY

    # 去重后返回
    return list(dict.fromkeys(paths))

# 全栈端口列表
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 873,
    1433, 1521, 3306, 3307, 3389, 5432, 6379, 6380, 7001, 7002,
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8088, 8089, 8443,
    9000, 9001, 9200, 9300, 27017, 27018, 6443, 10250, 10255, 10256,
    2379, 2380, 2376, 9090, 9093, 9100, 9115, 9117,
    11211, 5672, 15672, 15692, 4100, 4101,
    8848, 9848, 2181, 9092, 3000, 8090, 8761, 8888, 5601
]

# ==================== 工具类 ====================
if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class Logger:
    def __init__(self):
        pass
    def _log(self, level, message, color):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] [{level}] {message}{Colors.RESET}")
    def info(self, msg): self._log("INFO", msg, Colors.BLUE)
    def success(self, msg): self._log("SUCCESS", msg, Colors.GREEN)
    def warning(self, msg): self._log("WARNING", msg, Colors.YELLOW)
    def error(self, msg): self._log("ERROR", msg, Colors.RED)
    def raw(self, msg): print(msg)

class ScannerResult:
    def __init__(self):
        self.target_info = {}
        self.subdomains = []
        self.dns_records = []
        self.ports = []          # 爆破脚本核心读取字段：[{"port":22, "service":"ssh", "banner":"..."}]
        self.directories = []    # 包含后台登录路径，用于Web爆破
        self.fingerprints = []
        self.ssl_info = {}
        self.api_endpoints = []
        self.source_exposures = []
        self.security_issues = []
        self.scan_time = ""

# ==================== 核心扫描类 ====================
class AdvancedReconScanner:
    def __init__(self, url, logger):
        self.target_url = url
        self.logger = logger
        self.domain = ""
        self.ip = ""
        self.port = 80
        self.protocol = "http"
        self.clean_url = ""
        self.headers = {}
        self.html = ""
        self.result = ScannerResult()
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.wildcard_404 = False
        self.wildcard_404_len = -1
        self.wildcard_404_content = ""    # 1.3 通配符相似度比较用
        self.wildcard_404_redirect = ""
        self.behind_cdn = False           # 1.1 CDN检测标记
        self.cdn_provider = ""            # 1.1 CDN供应商名称

        self.parse_target()
        self.fetch_homepage()
        self.detect_cdn()                 # 1.1 必须在端口扫描前执行
        self.detect_wildcard_404()

    def parse_target(self):
        self.logger.info(f"解析目标 URL: {self.target_url}")
        try:
            if not self.target_url.startswith("http"):
                self.target_url = "http://" + self.target_url
            parsed = urllib.parse.urlparse(self.target_url)
            self.protocol = parsed.scheme
            self.domain = parsed.hostname
            self.port = parsed.port if parsed.port else (443 if self.protocol == "https" else 80)
            self.clean_url = f"{self.protocol}://{self.domain}" + (f":{self.port}" if parsed.port else "")
            
            self.result.target_info = {
                "original_url": self.target_url,
                "domain": self.domain,
                "ip": "",
                "protocol": self.protocol,
                "port": self.port
            }
            self.logger.success(f"解析完成: {self.domain} ({self.protocol})")

            try:
                self.ip = socket.gethostbyname(self.domain)
                self.result.target_info["ip"] = self.ip
                self.logger.success(f"解析 IP: {self.ip}")
                
                dns_ips = list(set([addr[4][0] for addr in socket.getaddrinfo(self.domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)]))
                self.result.dns_records.append({"type": "A/AAAA", "value": dns_ips})
            except socket.gaierror:
                self.logger.warning("域名解析失败，跳过端口扫描")
                self.ip = None
        except Exception as e:
            self.logger.error(f"解析失败: {e}")
            sys.exit(1)

    def fetch_homepage(self):
        try:
            resp = self.session.get(self.clean_url, timeout=TIMEOUT, verify=VERIFY_SSL)
            self.html = resp.text
            self.headers = dict(resp.headers)
            self.logger.success(f"首页获取成功: {resp.status_code} / {len(self.html)}字节")
        except Exception as e:
            self.logger.error(f"首页获取失败: {e}")

    # ---- 1.1 CDN/WAF检测 ----
    CDN_SIGNATURES = {
        "Cloudflare":     ["cf-ray", "cf-cache-status", "cf-request-id", "server: cloudflare"],
        "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache: hit from cloudfront"],
        "Akamai":         ["x-akamai-transformed", "x-akamai-request-id"],
        "Fastly":         ["x-served-by", "x-cache: hit, hit", "x-cache-hits"],
        "Sucuri":         ["x-sucuri-id", "x-sucuri-cache"],
        "Alibaba CDN":     ["ali-cdn", "x-cache: hit from aliyun"],
        "Tencent CDN":     ["x-nws-log-uuid", "x-cache-lookup: cache hit"],
    }

    def detect_cdn(self):
        """通过响应头特征识别CDN/WAF，影响后续端口扫描可信度"""
        self.logger.raw("\n" + "="*30 + " CDN/WAF检测 " + "="*30)
        if not self.headers:
            self.logger.info("无响应头，跳过CDN检测")
            return

        hl = {k.lower(): v.lower() for k, v in self.headers.items()}

        for provider, signatures in self.CDN_SIGNATURES.items():
            for sig in signatures:
                if ":" in sig:
                    key, val = sig.split(":", 1)
                    if hl.get(key.strip()) == val.strip():
                        self.behind_cdn = True
                        self.cdn_provider = provider
                        break
                else:
                    if sig in hl:
                        self.behind_cdn = True
                        self.cdn_provider = provider
                        break
            if self.behind_cdn:
                break

        # Server header 直标 CDN 的情况
        server = hl.get("server", "")
        if not self.behind_cdn:
            if "cloudflare" in server:
                self.behind_cdn = True
                self.cdn_provider = "Cloudflare"

        if self.behind_cdn:
            self.logger.warning(f"检测到 CDN: {self.cdn_provider} — 端口扫描结果将标注可信度")
            self.result.target_info["cdn"] = self.cdn_provider
        else:
            self.logger.success("未检测到 CDN/WAF，认为直连源站")
            self.result.target_info["cdn"] = None

    def detect_wildcard_404(self):
        url = f"{self.clean_url}/test_nonexist_{uuid.uuid4().hex[:8]}"
        try:
            resp = self.session.get(url, timeout=TIMEOUT, verify=VERIFY_SSL, allow_redirects=False)
            self.wildcard_404_len = len(resp.text)
            self.wildcard_404_content = resp.text   # 1.3 存储完整内容用于相似度比较
            if resp.status_code == 200:
                self.wildcard_404 = True
                self.logger.warning("检测到通配符404，已启用相似度过滤（阈值 85%）")
            elif resp.status_code in [301,302]:
                self.wildcard_404 = True
                self.wildcard_404_redirect = resp.headers.get("Location","")
        except:
            pass

    # 1. 子域名探测
    def scan_subdomains(self):
        if not SUBDOMAIN_SCAN_ENABLE or not self.domain:
            return
        self.logger.raw("\n" + "="*30 + " 子域名探测 " + "="*30)
        subdomains = set()

        # 被动查询
        try:
            resp = requests.get(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=10)
            if resp.ok:
                for cert in resp.json():
                    for name in cert["name_value"].split("\n"):
                        if name.endswith(self.domain) and "*" not in name and name != self.domain:
                            subdomains.add(name.strip().lower())
                self.logger.success(f"被动发现 {len(subdomains)} 个子域名")
        except:
            self.logger.warning("被动子域名查询失败")

        # 主动爆破
        def check_sub(sub):
            try:
                socket.gethostbyname(f"{sub}.{self.domain}")
                return f"{sub}.{self.domain}"
            except:
                return None
        with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
            for res in executor.map(check_sub, SUBDOMAIN_DICT):
                if res: subdomains.add(res)

        self.result.subdomains = sorted(list(subdomains))
        if self.result.subdomains:
            for sd in self.result.subdomains:
                self.logger.raw(f"  - {sd}")

    # 2. 端口扫描 + 深度指纹
    def deep_service_fingerprint(self, port, service):
        if not self.ip: return None
        # Redis
        if port == 6379:
            try:
                s = socket.socket(); s.settimeout(2)
                s.connect((self.ip, port)); s.send(b"INFO\r\n")
                data = s.recv(2048).decode(errors="ignore"); s.close()
                m = re.search(r"redis_version:([\d.]+)", data, re.I)
                return f"Redis {m.group(1)}" if m else "Redis"
            except: pass
        # MySQL
        if port == 3306:
            try:
                s = socket.socket(); s.settimeout(2)
                s.connect((self.ip, port))
                data = s.recv(1024).decode(errors="ignore"); s.close()
                m = re.search(r"([\d.]+)-\w+", data)
                return f"MySQL {m.group(1)}" if m else "MySQL"
            except: pass
        # SSH
        if port == 22:
            try:
                s = socket.socket(); s.settimeout(2)
                s.connect((self.ip, port))
                banner = s.recv(512).decode(errors="ignore").strip(); s.close()
                return banner[:50] if "SSH" in banner else None
            except: pass
        return None

    def scan_ports(self):
        if not self.ip:
            return
        self.logger.raw("\n" + "="*30 + " 端口扫描 " + "="*30)
        total_ports = len(COMMON_PORTS)
        self.logger.info(f"扫描 {total_ports} 个常用端口...")

        common_services = {
            21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns", 80:"http",
            110:"pop3", 143:"imap", 443:"https", 445:"microsoft-ds", 873:"rsync",
            1433:"mssql", 1521:"oracle", 3306:"mysql", 3389:"rdp",
            5432:"postgresql", 6379:"redis", 8080:"http-alt", 8443:"https-alt",
            9200:"elasticsearch", 27017:"mongodb", 8848:"nacos", 3000:"grafana"
        }

        progress = {"done": 0}
        import threading
        plock = threading.Lock()

        def check_port(port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            try:
                if s.connect_ex((self.ip, port)) == 0:
                    service = common_services.get(port, "unknown")
                    banner = ""
                    # HTTP类抓Banner
                    if service in ["http","https","http-alt","https-alt"]:
                        try:
                            if port in [443,8443]:
                                ctx = ssl._create_unverified_context()
                                sock = ctx.wrap_socket(s, server_hostname=self.domain)
                            else: sock = s
                            sock.sendall(f"GET / HTTP/1.1\r\nHost: {self.domain}\r\nConnection: close\r\n\r\n".encode())
                            raw = sock.recv(4096).decode(errors="ignore")
                            banner = raw.split("\r\n\r\n")[0]
                        except: pass
                    else:
                        try: banner = s.recv(1024).decode(errors="ignore").strip()
                        except: pass

                    deep_fp = self.deep_service_fingerprint(port, service)

                    # ---- 1.2 端口可信度分级 ----
                    if deep_fp:
                        confidence = "high"          # 有版本号指纹
                    elif banner:
                        confidence = "medium"        # 有Banner但无版本
                    elif service in ["http","https","http-alt","https-alt"] and banner:
                        confidence = "medium"
                    elif self.behind_cdn and not banner:
                        confidence = "cdn_noise"     # CDN噪音，大概率假阳性
                    elif not banner:
                        confidence = "low"           # 仅TCP握手，无回显
                    else:
                        confidence = "medium"

                    self.logger.success(f"开放: {port}/TCP [{service}] ({confidence}) {deep_fp if deep_fp else ''}")

                    self.result.ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner[:200] if banner else "",
                        "version": deep_fp if deep_fp else "",
                        "confidence": confidence     # 新增：可信度评级
                    })
                    if deep_fp:
                        self.result.fingerprints.append({"type":"Service", "value": deep_fp})
                    s.close()
            except:
                try: s.close()
                except: pass
            finally:
                with plock:
                    progress["done"] += 1

        with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
            self.logger.info(f"端口扫描进行中 ({total_ports} 个端口)...")
            executor.map(check_port, COMMON_PORTS)
            self.logger.success(f"端口扫描完成")

        # 1.2 汇总可信度分布
        conf_counts = {"high":0,"medium":0,"low":0,"cdn_noise":0}
        for p in self.result.ports:
            c = p.get("confidence","low")
            conf_counts[c] = conf_counts.get(c, 0) + 1
        total = len(self.result.ports)
        self.logger.success(f"共发现 {total} 个开放端口 "
                          f"(高可信:{conf_counts['high']} 中可信:{conf_counts['medium']} "
                          f"低可信:{conf_counts['low']} CDN噪音:{conf_counts['cdn_noise']})")

    # 3. 路径爆破 + 漏洞验证
    def verify_path_vuln(self, path, content):
        vulns = []
        pl = path.lower(); cl = content.lower()
        if ".git/head" in pl and "ref: refs/heads" in cl:
            vulns.append({"type":"Git源码泄露", "severity":"Critical", "description":"可下载完整Git仓库", "remediation":"删除.git目录并禁止访问"})
        if ".env" in pl and re.search(r"DB_PASSWORD|APP_KEY|SECRET_KEY", content, re.I):
            vulns.append({"type":"环境配置泄露", "severity":"Critical", "description":"包含数据库密码等敏感信息", "remediation":"禁止Web访问.env文件"})
        if "actuator/env" in pl and "propertySources" in cl:
            vulns.append({"type":"Actuator未授权", "severity":"High", "description":"可读取全部环境变量", "remediation":"增加身份认证"})
        if ("swagger" in pl or "openapi" in pl) and ("swagger" in cl or "openapi" in cl):
            vulns.append({"type":"Swagger未授权", "severity":"Medium", "description":"接口文档公开暴露", "remediation":"生产环境关闭或加鉴权"})
        if path.endswith((".zip",".tar.gz",".sql",".bak")):
            vulns.append({"type":"备份文件泄露", "severity":"High", "description":"可下载备份/源码文件", "remediation":"删除Web目录下备份文件"})
        return vulns

    def scan_directories(self):
        self.logger.raw("\n" + "="*30 + " 路径爆破与漏洞验证 " + "="*30)
        path_dict = load_path_dictionary()
        total_paths = len(path_dict)
        self.logger.info(f"爆破 {total_paths} 个敏感路径...")

        import threading
        dprog = {"done": 0, "hits": 0}
        dlock = threading.Lock()

        def check_path(path):
            url = f"{self.clean_url}/{path.lstrip('/')}"
            try:
                resp = self.session.get(url, timeout=TIMEOUT, verify=VERIFY_SSL, allow_redirects=False)
                code = resp.status_code
                if self.wildcard_404:
                    if code == 200 and self.wildcard_404_content:
                        ratio = SequenceMatcher(None, resp.text, self.wildcard_404_content).ratio()
                        if ratio > 0.85: return None
                    if code in [301,302] and resp.headers.get("Location","") == self.wildcard_404_redirect: return None
                if code in [200, 403, 301, 302]:
                    desc = {200:"存在", 403:"禁止访问", 301:"永久跳转", 302:"临时跳转"}[code]
                    if code in [301,302]: desc += f" -> {resp.headers.get('Location','')}"
                    with dlock: dprog["hits"] += 1
                    return {"path": url, "status": code, "description": desc, "content": resp.text[:1000]}
            except: pass
            finally:
                with dlock:
                    dprog["done"] += 1
                    if dprog["done"] % 50 == 0 or dprog["done"] == total_paths:
                        pct = dprog["done"] * 100 // total_paths
                        sys.stdout.write(f"\r  [{dprog['done']}/{total_paths} {pct}%] 命中: {dprog['hits']}  ")
                        sys.stdout.flush()
            return None

        with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
            results = list(executor.map(check_path, path_dict))
        print()  # 换行后展示命中列表

        for res in results:
            if res:
                self.logger.success(f"命中: {res['path']} [{res['status']}]")
                self.result.directories.append(res)
                if res["content"]:
                    for v in self.verify_path_vuln(res["path"], res["content"]):
                        v["path"] = res["path"]
                        self.result.security_issues.append(v)
                        self.logger.warning(f"  漏洞确认: [{v['severity']}] {v['type']}")

    # 4. 指纹识别
    def detect_fingerprints(self):
        self.logger.raw("\n" + "="*30 + " 技术栈指纹识别 " + "="*30)
        detected = []
        hl = self.html.lower() if self.html else ""

        if hl:
            if "/wp-content/" in hl: detected.append("WordPress (CMS)")
            if "drupal.settings" in hl: detected.append("Drupal (CMS)")
            if "thinkphp" in hl: detected.append("ThinkPHP (PHP)")
            if "whitelabel error page" in hl: detected.append("Spring Boot (Java)")
            if "csrfmiddlewaretoken" in hl: detected.append("Django (Python)")
            if "data-v-" in hl: detected.append("Vue.js (前端)")
            if "reactroot" in hl: detected.append("React (前端)")
            if "jquery.min.js" in hl: detected.append("jQuery")

        server = self.headers.get("Server", "").lower()
        if "nginx" in server: detected.append("Nginx (Web服务器)")
        elif "apache" in server: detected.append("Apache (Web服务器)")
        elif "iis" in server: detected.append("IIS (Web服务器)")
        elif not server:
            # 1.5 无Server头 + CDN检测 → 明确标记
            if self.behind_cdn:
                detected.append(f"疑似 {self.cdn_provider} 反向代理（无Server头）")
            else:
                detected.append("Server头隐藏（可能为CDN/反向代理）")

        self.result.fingerprints.extend([{"type":"Tech", "value":x} for x in detected])
        for fp in detected:
            self.logger.raw(f"  - {fp}")

        # SSL检查
        if self.protocol == "https" and self.ip:
            self.logger.raw("\n" + "="*30 + " SSL配置检查 " + "="*30)
            try:
                ctx = ssl._create_unverified_context()
                with socket.create_connection((self.ip, self.port), timeout=TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        self.result.ssl_info = {
                            "protocol": ssock.version(),
                            "cipher": ssock.cipher()[0],
                            "cert_subject": str(ssock.getpeercert().get("subject",""))
                        }
                        self.logger.success(f"协议: {ssock.version()}, 套件: {ssock.cipher()[0]}")
            except Exception as e:
                self.logger.warning(f"SSL检查失败: {e}")

    # 5. 安全头检查
    def scan_security_headers(self):
        self.logger.raw("\n" + "="*30 + " 安全响应头检查 " + "="*30)
        if not self.headers:
            self.logger.error("无响应头，跳过")
            return
        sec_heads = {
            "X-Frame-Options":"防点击劫持", "Content-Security-Policy":"防XSS",
            "Strict-Transport-Security":"强制HTTPS", "X-Content-Type-Options":"防MIME嗅探",
            "Referrer-Policy":"防Referrer泄露", "Permissions-Policy":"浏览器权限控制"
        }
        hl = {k.lower():v for k,v in self.headers.items()}
        for h, desc in sec_heads.items():
            if h.lower() in hl:
                self.logger.success(f"已配置: {h}")
            else:
                self.logger.warning(f"缺失: {h} ({desc})")
                self.result.security_issues.append({
                    "type": "Missing Header", "path": self.clean_url,
                    "description": f"缺失安全头 {h}", "severity": "Medium",
                    "remediation": f"在Web服务器配置中启用 {h}"
                })

    # 6. JS提取API（增强版——1.4）
    def extract_apis_from_js(self):
        if not self.html: return
        self.logger.raw("\n" + "="*30 + " JS动态API提取 " + "="*30)
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', self.html)

        # 1.4 也抓内联 script 块内容
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', self.html, re.DOTALL)
        combined_js_content = "\n".join(inline_scripts) if inline_scripts else ""

        # 1.4 多模式正则：经典URL字符串 + fetch/axios调用 + 动态路由参数
        api_patterns = [
            r'["\']((?:/api/|/v\d+/)[a-zA-Z0-9_/\-]+)["\']',             # 字符串字面量
            r"""fetch\s*\(\s*["']([^"']+)["']""",                          # fetch("url")
            r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*["']([^"']+)""", # axios.get("url")
            r"""XMLHttpRequest.*?\.open\s*\(\s*["']\w+["']\s*,\s*["']([^"']+)""", # XHR.open
            r'["\']((?:/api/|/v\d+/)[a-zA-Z0-9_/\-]*:[a-zA-Z0-9_]+)["\']',  # 动态路由 /api/user/:id
        ]
        apis = set()

        def parse_js(js_path):
            try:
                url = js_path if js_path.startswith("http") else f"{self.clean_url}{js_path if js_path.startswith('/') else '/'+js_path}"
                resp = self.session.get(url, timeout=TIMEOUT, verify=VERIFY_SSL)
                content = resp.text
                found = set()
                for pat in api_patterns:
                    found.update(re.findall(pat, content))
                return found
            except:
                return set()

        # 外部 JS
        if js_urls:
            self.logger.info(f"发现 {len(js_urls)} 个外部JS文件 + {len(inline_scripts)} 个内联脚本块")
            with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
                for res in executor.map(parse_js, js_urls):
                    apis.update(res)

        # 1.4 内联 script 内容
        for pat in api_patterns:
            apis.update(re.findall(pat, combined_js_content))

        if apis:
            self.logger.success(f"提取到 {len(apis)} 个API路径")
            for api in sorted(apis):
                self.result.api_endpoints.append({"path": api, "source": "JS提取"})
                self.logger.raw(f"  - {api}")
        elif js_urls or inline_scripts:
            self.logger.info("外部JS和内联脚本中未提取到API路径")

    def get_result_dict(self):
        self.result.scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {
            "target_info": self.result.target_info,
            "scan_time": self.result.scan_time,
            "subdomains": self.result.subdomains,
            "dns_records": self.result.dns_records,
            "ports": self.result.ports,
            "directories": self.result.directories,
            "fingerprints": self.result.fingerprints,
            "ssl_info": self.result.ssl_info,
            "api_endpoints": self.result.api_endpoints,
            "source_exposures": self.result.source_exposures,
            "security_issues": self.result.security_issues
        }

# ==================== 主函数 ====================
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logger = Logger()

    # 1.6 支持命令行参数指定目标
    target = TARGET_URL  # 默认值
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if not target.startswith("http"):
            target = "https://" + target
        logger.info(f"使用命令行目标: {target}")
    elif TARGET_URL:
        logger.info(f"使用配置文件目标: {target}")
    else:
        logger.error("未指定目标地址，用法: python saomiao.py <URL>")
        sys.exit(1)

    # Banner
    print(f"""{Colors.RED}{Colors.BOLD}
   ███████  █████  ██████  ███    ███ ██  █████  ██████  
   ██      ██   ██ ██   ██ ████  ████ ██ ██   ██ ██   ██ 
   ███████ ███████ ██████  ██ ████ ██ ██ ███████ ██████  
        ██ ██   ██ ██   ██ ██  ██  ██ ██ ██   ██ ██   ██ 
   ███████ ██   ██ ██   ██ ██      ██ ██ ██   ██ ██   ██ 
                    bee-py · 资产测绘引擎 v2.2
{Colors.RESET}
目标: {target}
线程: {THREAD_COUNT} | 超时: {TIMEOUT}s
""")

    # 自动下载开源字典（如果本地没有）
    try:
        from tools.deps import ensure_dep
        for dict_id in ["seclists_admin", "seclists_common", "lfi_payloads"]:
            ensure_dep(dict_id, auto=True)
    except ImportError:
        pass  # 没装 deps.py 也不影响运行

    scanner = AdvancedReconScanner(target, logger)
    scanner.scan_subdomains()
    scanner.scan_ports()
    scanner.scan_directories()
    scanner.detect_fingerprints()
    scanner.scan_security_headers()
    scanner.extract_apis_from_js()

    # 保存结果
    host = re.sub(r'[^a-zA-Z0-9.-]', '', scanner.domain)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = os.path.join(OUTPUT_DIR, f"scan_{host}_{ts}.json")
    
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(scanner.get_result_dict(), f, ensure_ascii=False, indent=2)
    
    logger.raw("\n" + "="*60)
    logger.success(f"扫描完成，结果已保存至: {json_file}")
    logger.info(f"运行 python diaodu.py 打开调度台选择利用工具")
    return json_file

if __name__ == "__main__":
    interrupted = False
    try:
        main()
    except KeyboardInterrupt:
        interrupted = True
        print(f"\n{Colors.YELLOW}[!] 用户中断扫描 — 已完成的模块结果已保存{Colors.RESET}")
        sys.exit(0)