#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
saomiao.py - 全栈资产测绘与漏洞发现引擎 v3.0
功能：子域名探测、端口扫描、路径爆破、指纹识别、漏洞验证、安全头检测
v3.0新功能：自适应速率控制、多IP代理轮询、未授权检测、中间件POC、架构分层

⚠️ 【重要法律免责声明】
本工具仅用于授权的安全测试与教育目的。
使用本工具进行未经授权的扫描/测试/攻击是违法行为。
使用者需自行承担因不当使用本工具产生的一切法律责任。
使用本工具即表示您同意遵守所有适用的法律法规。
"""

import socket
import argparse
import urllib.parse
import datetime
import sys
import json
import re
import ssl
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

from utils import (
    Colors, create_secure_session, sanitize_domain, RateLimiter, 
    ProxyPool, CancelToken, is_wildcard_404, validate_target_url,
    check_dict_updates
)

# ==================== 配置区 ====================
THREAD_COUNT = 50
TIMEOUT = 8
VERIFY_SSL = True  # 默认启用SSL验证
# 输出目录适配新结构，兼容旧目录
OUTPUT_DIR = "./data/scans"
_OLD_OUTPUT_DIR = "./scans"
if not os.path.exists(OUTPUT_DIR) and os.path.exists(_OLD_OUTPUT_DIR):
    OUTPUT_DIR = _OLD_OUTPUT_DIR
os.makedirs(OUTPUT_DIR, exist_ok=True)
PROXY_FILE = "./proxies.txt"  # 代理IP列表文件，每行一个
RANDOM_UA = True
AUTO_UPDATE_DICTS = True
RATE_LIMIT_ENABLED = True
INITIAL_DELAY = 0.05  # 初始请求间隔（秒）——不拦截就猛爆破
MIN_DELAY = 0.01
MAX_DELAY = 10.0

# 子域名配置
SUBDOMAIN_SCAN_ENABLE = True
INTERNAL_SUBDOMAIN_DICT = [
    "www", "api", "admin", "test", "dev", "prod", "staging", "git", "jenkins",
    "k8s", "nacos", "grafana", "prometheus", "elasticsearch", "redis", "mysql",
    "console", "dashboard", "manage", "openapi", "doc", "docs", "static", "cdn",
    "mail", "smtp", "pop3", "imap", "ftp", "sftp", "backup", "db", "database",
    "vpn", "oa", "crm", "erp", "wiki", "blog", "shop", "mall", "m", "wap",
    "mobile", "app", "service", "services", "ws", "wss", "proxy", "gateway"
]

HEADERS = {}

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
    # ===== 管理面板专用路径（IP+端口+路径 找登录页）=====
    # 宝塔面板 BT-Panel（默认8888端口，安全入口是随机8位字符，但常见配置会保留这些）
    "btpanel/", "btpanel/login", "btpanel/site", "btpanel/files", "btpanel/crontab",
    "btpanel/database", "btpanel/firewall", "btpanel/ssl", "btpanel/soft", "btpanel/config",
    "safe/", "safe/login", "bt-panel/", "www/", "panel/", "panel/login",
    # 1Panel 面板（默认8090端口，入口路径可配置）
    "1panel/", "1panel/login", "apps/", "websites/", "cronjobs/", "databases/",
    # phpMyAdmin（数据库管理后台，常挂在888/80端口）
    "phpmyadmin/", "phpMyAdmin/", "phpmyadmin/index.php", "phpmyadmin/themes/",
    "pma/", "PMA/", "mysql/", "mysqladmin/", "mysql-admin/", "dbadmin/",
    # Adminer（轻量数据库管理）
    "adminer.php", "adminer/", "adminer/adminer.php",
    # Tomcat 管理后台（默认8080端口，manager/manager-gui）
    "manager/html", "manager/status", "manager/text", "host-manager/html",
    "manager/jmxproxy", "manager/text/list",
    # Nginx/Apache 管理界面
    "nginx/", "apache/", "server-status", "server-info", "status/",
    # Webmin/Usermin（默认10000端口）
    "webmin/", "usermin/",
    # cPanel/DirectAdmin（默认2082/2083/2222端口）
    "cpanel/", "cpanel/login", "webmail/", "whm/", "frontend/", "directadmin/",
    # 各种CMS后台
    "administrator/", "admin/login.php", "admin/index.php", "admincp/", "admincp/login.php",
    "wp-admin/login.php", "wp-login.php", "xmlrpc.php", "wp-admin/admin-ajax.php",
    "user/login", "user/register", "member/login", "account/login", "account/signin",
    "backend/", "backend/login", "system/", "system/login", "cp/", "cp/login",
    "manage/login", "manager/", "manager/login", "console/login", "dashboard/login",
    # 国产CMS/框架后台
    "dede/login.php", "dede/", "e/admin/", "e/admin/index.php", "phpcms/login",
    "destoon/admin/", "discuz/admin.php", "discuz/uc_server/admin.php", "empireadmin/",
    #运维监控面板
    "zabbix/", "grafana/login", "grafana/", "kibana/", "prometheus/", "nagios/",
    "jenkins/login", "jenkins/manage", "jenkins/script", "sonar/",
    # 容器/编排管理
    "portainer/", "rancher/", "kubernetes/", "k8s/dashboard/", "swarm/",
    "phpinfo.php", "info.php", "test.php", "tz.php", "status", "server-status",
    "actuator/env", "actuator/health", "actuator", "api/v1/", "v1/api", "swagger-ui.html",
    "api/swagger-ui.html", "swagger/index.html", "v1/swagger.json", "swagger.json",
    "zabbix/", "jenkins/", "solr/", "consul/", "etcd/", "grafana/", "kibana/", "prometheus/",
    ".aws/credentials", ".azure/credentials", ".gcp/credentials",
    ".github/workflows/main.yml", ".gitlab-ci.yml", ".travis.yml", "Jenkinsfile",
    "docker-compose.yml", "docker-compose.override.yml", "daemon.json",
    "src/", "source/", "code/", "lib/", "vendor/", "node_modules/.cache/",
    "__pycache__/", "build/", "dist/", ".gradle/", ".m2/", ".npm/",
    "api-docs/", "apidoc/", "openapi.json", "openapi.yaml", "graphql/", "api/graphql", "api/health",
    ".svn/entries", ".hg/store/00manifest.i", "CVS/Root",
    "WEB-INF/web.xml", "META-INF/MANIFEST.MF",
    "phpmyadmin/", "pma/", "myadmin/", "mysqladmin/",
    "shell.php", "cmd.php", "eval.php", "test.jsp", "cmd.asp",
    ".DS_Store", "Thumbs.db", "error_log", "debug.log"
]

def load_path_dictionary():
    """从 dicts/ 目录加载所有路径字典（内置+本地+开源），合并去重，兼容旧dict目录"""
    dict_dir = os.path.join(os.path.dirname(__file__), "dicts")
    old_dict_dir = os.path.join(os.path.dirname(__file__), "dict")
    if not os.path.exists(dict_dir) and os.path.exists(old_dict_dir):
        dict_dir = old_dict_dir
    os.makedirs(dict_dir, exist_ok=True)
    paths = []
    seen = set()

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

    # 3. 加载子域名字典
    subdomain_extra = []
    subdomain_path = os.path.join(dict_dir, "subdomains.txt")
    if os.path.exists(subdomain_path):
        with open(subdomain_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    subdomain_extra.append(line)
        if subdomain_extra:
            global SUBDOMAIN_SCAN_ENABLE
            print(f"{Colors.CYAN}[字典] 加载子域名字典: +{len(subdomain_extra)} 条{Colors.RESET}")

    return list(dict.fromkeys(paths)), subdomain_extra

# 全栈端口列表 - 覆盖常见服务、中间件、数据库、未授权访问端口
COMMON_PORTS = [
    # 基础服务
    21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 993, 995,
    # 数据库
    1433, 1434, 1521, 1522, 1523, 1524, 1830, 2375, 2376, 2379, 2380, 3050, 3306, 3307, 3308, 3389, 5432, 5433, 5984, 6379, 6380, 6381, 6382, 7000, 7001, 7002, 7003, 7004, 7005,
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8443, 8888,
    # 大数据/中间件
    9000, 9001, 9042, 9090, 9091, 9092, 9093, 9200, 9201, 9300, 9301, 9848, 9849, 11211, 11212, 15672, 15673, 15674, 15675, 15692, 2181, 2182, 27017, 27018, 27019, 27020,
    # Kubernetes/云原生
    6443, 8080, 8443, 10250, 10255, 10256, 10257, 10258, 10259, 10260,
    # DevOps/监控
    3000, 3001, 5601, 5602, 8090, 8761, 8848, 9100, 9115, 9117, 9153,
    # VNC/远程桌面
    5900, 5901, 5902, 5903, 5984,
    # 其他
    3690, 4100, 4101, 5000, 5005, 5432, 6666, 7777, 9999, 10000
]

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
        self.ports = []
        self.directories = []
        self.fingerprints = []
        self.ssl_info = {}
        self.api_endpoints = []
        self.source_exposures = []
        self.security_issues = []
        self.scan_time = ""
        self.proxy_used = 0
        self.rate_limit_stats = {}

class AdvancedReconScanner:
    def __init__(self, url, logger, args):
        self.target_url = url
        self.logger = logger
        self.args = args
        self.domain = ""
        self.ip = ""
        self.port = 80
        self.protocol = "http"
        self.clean_url = ""
        self.html = ""
        self.headers = {}
        self.result = ScannerResult()
        
        # 代理池和速率限制
        self.proxy_pool = None
        self.rate_limiter = None
        if args.proxy_file or os.path.exists(PROXY_FILE):
            pf = args.proxy_file or PROXY_FILE
            self.proxy_pool = ProxyPool(proxy_file=pf)
            if len(self.proxy_pool) > 0:
                self.logger.info(f"代理池已启用，共 {len(self.proxy_pool)} 个代理")
                self.result.proxy_used = len(self.proxy_pool)
        
        if args.rate_limit:
            self.rate_limiter = RateLimiter(
                min_delay=args.min_delay,
                max_delay=args.max_delay,
                initial_delay=args.delay,
                preset=getattr(args, 'rate_preset', 'normal')
            )
            mode_text = {"fast": "极速", "normal": "标准", "safe": "安全"}[getattr(args, 'rate_preset', 'normal')]
            self.logger.info(f"智能速率保护已启用 ({mode_text}模式)，初始间隔 {args.delay}s，线程数 {args.threads}")
        
        # 创建安全会话
        self.session = create_secure_session(
            verify_ssl=not args.insecure,
            timeout=args.timeout,
            retries=3,
            proxy_pool=self.proxy_pool,
            rate_limiter=self.rate_limiter,
            random_ua=RANDOM_UA,
            custom_headers=HEADERS
        )
        
        self.cancel_token = CancelToken()
        self.wildcard_404 = False
        self.wildcard_404_len = -1
        self.wildcard_404_content = ""
        self.wildcard_404_title = None
        self.wildcard_404_redirect = ""
        self.behind_cdn = False
        self.cdn_provider = ""
        self.dns_ips = []

        self.parse_target()
        self.fetch_homepage()
        self.detect_cdn()
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
                "port": self.port,
                "behind_cdn": False,
                "proxy_enabled": self.proxy_pool is not None and len(self.proxy_pool) > 0
            }
            self.logger.success(f"解析完成: {self.domain} ({self.protocol})")

            try:
                self.ip = socket.gethostbyname(self.domain)
                self.result.target_info["ip"] = self.ip
                self.logger.success(f"解析 IP: {self.ip}")
                
                self.dns_ips = list(set([addr[4][0] for addr in socket.getaddrinfo(self.domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)]))
                self.result.dns_records.append({"type": "A/AAAA", "value": self.dns_ips})
                
                # CDN检测增强：多个IP解析且IP分布很广，大概率是CDN
                if len(self.dns_ips) > 5:
                    self.logger.warning(f"DNS解析到 {len(self.dns_ips)} 个IP，疑似CDN/负载均衡")
            except socket.gaierror:
                self.logger.warning("域名解析失败，跳过端口扫描")
                self.ip = None
        except Exception as e:
            self.logger.error(f"解析失败: {e}")
            sys.exit(1)

    def fetch_homepage(self):
        try:
            resp = self.session.get(self.clean_url, timeout=self.args.timeout)
            self.html = resp.text
            self.headers = dict(resp.headers)
            self.logger.success(f"首页获取成功: {resp.status_code} / {len(self.html)}字节")
        except Exception as e:
            self.logger.error(f"首页获取失败: {e}")

    CDN_SIGNATURES = {
        "Cloudflare":     ["cf-ray", "cf-cache-status", "cf-request-id", "server: cloudflare"],
        "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache: hit from cloudfront"],
        "Akamai":         ["x-akamai-transformed", "x-akamai-request-id"],
        "Fastly":         ["x-served-by", "x-cache: hit, hit", "x-cache-hits"],
        "Sucuri":         ["x-sucuri-id", "x-sucuri-cache"],
        "Alibaba CDN":     ["ali-cdn", "x-cache: hit from aliyun", "server: tengine"],
        "Tencent CDN":     ["x-nws-log-uuid", "x-cache-lookup: cache hit", "server: nginx/1."],
        "Baidu CDN":       ["x-bd-cache", "server: jsp3"],
        "Huawei CDN":      ["x-hws-cache", "x-cache: hit from huawei"],
        "CDN77":          ["x-cdn77-cache", "server: cdn77"],
        "CloudFront":      ["x-cache: hit from cloudfront", "via: cloudfront"],
        "Google CDN":      ["x-goog-cache", "server: ghs"],
        "Incapsula":       ["x-iinfo", "x-cdn: incapsula"],
        "StackPath":       ["x-sp-cache", "server: nginx"],
    }

    def detect_cdn(self):
        """通过响应头特征+DNS解析识别CDN/WAF"""
        self.logger.raw("\n" + "="*30 + " CDN/WAF检测 " + "="*30)
        if not self.headers:
            self.logger.info("无响应头，跳过CDN检测")
            return

        hl = {k.lower(): v.lower() for k, v in self.headers.items()}

        for provider, signatures in self.CDN_SIGNATURES.items():
            for sig in signatures:
                if ":" in sig:
                    key, val = sig.split(":", 1)
                    if hl.get(key.strip(), "").startswith(val.strip()):
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

        server = hl.get("server", "")
        if not self.behind_cdn:
            for cdn_name in ["cloudflare", "cdn", "akamai", "fastly", "tengine", "cdn77"]:
                if cdn_name in server:
                    self.behind_cdn = True
                    self.cdn_provider = cdn_name.capitalize()
                    break

        # 多IP判定
        if not self.behind_cdn and len(self.dns_ips) > 8:
            self.behind_cdn = True
            self.cdn_provider = "疑似CDN/负载均衡(多IP)"
        
        # ASN/IP范围判定（简化版，常见CDN CIDR特征）
        if not self.behind_cdn and self.ip:
            ip_parts = list(map(int, self.ip.split('.')))
            if ip_parts[0] in [104, 172, 103] and len(self.dns_ips) > 3:
                self.behind_cdn = True
                self.cdn_provider = "疑似Cloudflare/Akamai"

        if self.behind_cdn:
            self.logger.warning(f"检测到 CDN: {self.cdn_provider}")
            if self.proxy_pool and len(self.proxy_pool) > 0:
                self.logger.info("已启用代理池，端口扫描将通过代理尝试")
            else:
                self.logger.warning("未使用代理，端口扫描结果将仅做参考")
            self.result.target_info["cdn"] = self.cdn_provider
            self.result.target_info["behind_cdn"] = True
        else:
            self.logger.success("未检测到 CDN/WAF，直连源站")
            self.result.target_info["cdn"] = None

    def detect_wildcard_404(self):
        import uuid
        url = f"{self.clean_url}/test_nonexist_{uuid.uuid4().hex[:10]}"
        try:
            resp = self.session.get(url, timeout=self.args.timeout, allow_redirects=False)
            self.wildcard_404_len = len(resp.text)
            self.wildcard_404_content = resp.text
            
            title_match = re.search(r"<title>(.*?)</title>", resp.text, re.I | re.S)
            if title_match:
                self.wildcard_404_title = title_match.group(1).strip()
            
            if resp.status_code == 200:
                self.wildcard_404 = True
                self.logger.warning("检测到通配符404，已启用智能多级过滤")
            elif resp.status_code in [301,302]:
                self.wildcard_404 = True
                self.wildcard_404_redirect = resp.headers.get("Location","")
                self.logger.warning("检测到404跳转，已启用重定向过滤")
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            pass

    def scan_subdomains(self):
        if not SUBDOMAIN_SCAN_ENABLE or not self.domain:
            return
        self.logger.raw("\n" + "="*30 + " 子域名探测 " + "="*30)
        subdomains = set()
        extra_subs = []
        _, extra_subs = load_path_dictionary()

        try:
            self.logger.info("正在通过证书透明度查询子域名...")
            resp = self.session.get(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=15)
            if resp.ok:
                for cert in resp.json():
                    for name in cert["name_value"].split("\n"):
                        name = name.strip().lower()
                        if name.endswith(self.domain) and "*" not in name and name != self.domain:
                            subdomains.add(name)
                self.logger.success(f"被动发现 {len(subdomains)} 个子域名")
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.logger.warning("被动子域名查询失败，继续主动爆破")

        sub_dict = list(INTERNAL_SUBDOMAIN_DICT)
        if extra_subs:
            sub_dict.extend(extra_subs)
        sub_dict = list(set(sub_dict))

        def check_sub(sub):
            if self.cancel_token.is_cancelled():
                return None
            try:
                socket.gethostbyname(f"{sub}.{self.domain}")
                return f"{sub}.{self.domain}"
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                return None

        self.logger.info(f"正在爆破 {len(sub_dict)} 个子域名...")
        with ThreadPoolExecutor(max_workers=min(30, self.args.threads)) as executor:
            futures = [executor.submit(check_sub, sub) for sub in sub_dict]
            for future in as_completed(futures):
                try:
                    res = future.result(timeout=1)
                    if res:
                        subdomains.add(res)
                except (KeyboardInterrupt, SystemExit):
                    self.cancel_token.cancel()
                    break
                except Exception:
                    pass

        self.result.subdomains = sorted(list(subdomains))
        if self.result.subdomains:
            self.logger.success(f"共发现 {len(self.result.subdomains)} 个子域名:")
            for sd in self.result.subdomains[:50]:
                self.logger.raw(f"  - {sd}")
            if len(self.result.subdomains) > 50:
                self.logger.raw(f"  ... 还有 {len(self.result.subdomains)-50} 个")

    def deep_service_fingerprint(self, port, service):
        if not self.ip: return None
        def _connect_recv(port, send_data=None, recv_size=2048):
            try:
                s = socket.socket()
                s.settimeout(3)
                s.connect((self.ip, port))
                if send_data:
                    s.send(send_data)
                data = s.recv(recv_size).decode(errors="ignore")
                s.close()
                return data
            except:
                return None

        if port == 6379:
            data = _connect_recv(port, b"INFO\r\n")
            if data:
                m = re.search(r"redis_version:([\d.]+)", data, re.I)
                return f"Redis {m.group(1)}" if m else "Redis"
        if port == 3306:
            data = _connect_recv(port)
            if data:
                m = re.search(r"([\d.]+)-\w+", data)
                return f"MySQL {m.group(1)}" if m else "MySQL"
        if port == 22:
            data = _connect_recv(port)
            if data and "SSH" in data:
                return data.strip()[:80]
        if port == 21:
            data = _connect_recv(port)
            if data and ("FTP" in data or "220" in data):
                return data.strip()[:80]
        if port == 25:
            data = _connect_recv(port)
            if data and ("SMTP" in data or "220" in data):
                return data.strip()[:80]
        if port == 3389:
            return "RDP (Remote Desktop)"
        if port == 5432:
            data = _connect_recv(port)
            if data:
                return "PostgreSQL"
        if port == 27017:
            return "MongoDB"
        return None

    def scan_ports(self):
        if not self.ip:
            return
        self.logger.raw("\n" + "="*30 + " 端口扫描 " + "="*30)
        total_ports = len(COMMON_PORTS)
        self.logger.info(f"扫描 {total_ports} 个常用端口...")
        if self.behind_cdn and not self.proxy_pool:
            self.logger.warning("目标使用CDN且未配置代理，非HTTP端口扫描结果可能不准确")

        common_services = {
            # 基础服务
            21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns", 69:"tftp", 80:"http", 88:"kerberos",
            110:"pop3", 111:"rpcbind", 123:"ntp", 135:"msrpc", 139:"netbios", 143:"imap", 161:"snmp",
            389:"ldap", 443:"https", 445:"smb", 465:"smtps", 514:"syslog", 587:"submission",
            636:"ldaps", 873:"rsync", 993:"imaps", 995:"pop3s",
            # 数据库
            1433:"mssql", 1434:"mssql-monitor", 1521:"oracle", 3050:"firebird",
            3306:"mysql", 3307:"mysql-alt", 3389:"rdp", 5432:"postgresql", 5433:"postgresql-alt",
            5984:"couchdb", 6379:"redis", 6380:"redis-alt", 9042:"cassandra", 27017:"mongodb", 27018:"mongodb-shard",
            # Web中间件/应用服务
            7001:"weblogic", 7002:"weblogic-adm", 8000:"http-alt", 8001:"http-alt", 8005:"tomcat-ajp",
            8009:"tomcat-ajp", 8080:"http-alt", 8081:"http-alt", 8088:"hadoop-yarn", 8443:"https-alt",
            8888:"http-alt", 9000:"sonar", 9090:"http-alt", 9200:"elasticsearch", 9300:"elasticsearch-tcp",
            # DevOps/云原生
            2375:"docker", 2376:"docker-tls", 2379:"etcd", 2380:"etcd-peer", 5601:"kibana",
            6443:"kubernetes-api", 8080:"http-alt", 8761:"eureka", 8848:"nacos", 9848:"nacos-grpc",
            10250:"kubelet", 10255:"kubelet-readonly", 15672:"rabbitmq-mgmt", 2181:"zookeeper",
            # 缓存/消息队列
            11211:"memcached", 5672:"amqp", 9092:"kafka",
            # 其他
            3000:"grafana", 3690:"svn", 4100:"squid", 5000:"upnp", 5005:"rmi", 5900:"vnc", 5901:"vnc",
            6666:"irc", 7777:"cpanel", 9999:"abyss", 10000:"webmin"
        }

        progress = {"done": 0}
        import threading
        plock = threading.Lock()

        def check_port(port):
            if self.cancel_token.is_cancelled():
                return
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(min(2, self.args.timeout/2))
            try:
                if s.connect_ex((self.ip, port)) == 0:
                    service = common_services.get(port, "unknown")
                    banner = ""
                    if service in ["http","https","http-alt","https-alt"]:
                        try:
                            ctx = None
                            if port in [443,8443]:
                                ctx = ssl._create_unverified_context()
                                sock = ctx.wrap_socket(s, server_hostname=self.domain)
                            else: sock = s
                            sock.sendall(f"GET / HTTP/1.1\r\nHost: {self.domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
                            raw = sock.recv(4096).decode(errors="ignore")
                            if "\r\n\r\n" in raw:
                                banner = raw.split("\r\n\r\n")[0]
                            else:
                                banner = raw[:500]
                        except: pass
                    else:
                        try: 
                            banner = s.recv(512).decode(errors="ignore").strip()
                        except: pass

                    deep_fp = self.deep_service_fingerprint(port, service)

                    if deep_fp and len(deep_fp) > 5:
                        confidence = "high"
                    elif banner and len(banner) > 10:
                        confidence = "medium"
                    elif self.behind_cdn and not banner and service in ["http","https"]:
                        confidence = "cdn_noise"
                    elif not banner:
                        confidence = "low"
                    else:
                        confidence = "medium"

                    self.logger.success(f"开放: {port}/TCP [{service}] ({confidence}) {deep_fp if deep_fp else ''}")

                    self.result.ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner[:300] if banner else "",
                        "version": deep_fp if deep_fp else "",
                        "confidence": confidence
                    })
                    if deep_fp:
                        self.result.fingerprints.append({"type":"Service", "value": deep_fp})
            except (KeyboardInterrupt, SystemExit):
                self.cancel_token.cancel()
            except:
                pass
            finally:
                try: s.close()
                except: pass
                with plock:
                    progress["done"] += 1
                    if progress["done"] % 20 == 0:
                        pct = progress["done"] * 100 // total_ports
                        sys.stdout.write(f"\r  进度: {progress['done']}/{total_ports} {pct}%   ")
                        sys.stdout.flush()

        with ThreadPoolExecutor(max_workers=min(50, self.args.threads*2)) as executor:
            futures = [executor.submit(check_port, p) for p in COMMON_PORTS]
            try:
                for future in as_completed(futures, timeout=120):
                    future.result()
            except (KeyboardInterrupt, TimeoutError):
                self.cancel_token.cancel()
                self.logger.warning("\n端口扫描被中断，已保存部分结果")

        sys.stdout.write("\r" + " " * 60 + "\r")
        conf_counts = {"high":0,"medium":0,"low":0,"cdn_noise":0}
        for p in self.result.ports:
            c = p.get("confidence","low")
            conf_counts[c] = conf_counts.get(c, 0) + 1
        total = len(self.result.ports)
        self.logger.success(f"端口扫描完成: {total} 个开放端口 "
                          f"(高可信:{conf_counts['high']} 中可信:{conf_counts['medium']} "
                          f"低可信:{conf_counts['low']} CDN噪音:{conf_counts['cdn_noise']})")

    def verify_path_vuln(self, path, content):
        vulns = []
        pl = path.lower(); cl = content.lower()
        if ".git/head" in pl and "ref: refs/heads" in cl:
            vulns.append({"type":"Git源码泄露", "severity":"Critical", "description":"可下载完整Git仓库获取源码", "remediation":"删除.git目录并配置服务器禁止访问"})
        if ".env" in pl and re.search(r"(DB_PASSWORD|APP_KEY|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY|TOKEN|PASSWORD)\s*=", content, re.I):
            vulns.append({"type":"环境配置泄露", "severity":"Critical", "description":"包含数据库密码/API密钥等敏感信息", "remediation":"禁止Web访问配置文件，移出Web目录"})
        if "actuator/env" in pl and ("propertysources" in cl or "spring" in cl.lower()):
            vulns.append({"type":"Spring Actuator未授权", "severity":"High", "description":"可读取全部环境变量和配置", "remediation":"增加身份认证，生产环境禁用actuator端点"})
        if ("swagger" in pl or "openapi" in pl) and ("swagger" in cl or "openapi" in cl):
            vulns.append({"type":"Swagger接口文档暴露", "severity":"Medium", "description":"API接口文档公开泄露", "remediation":"生产环境关闭Swagger或增加鉴权"})
        if path.endswith((".zip",".tar.gz",".sql",".bak",".rar",".7z")) and len(content) > 100:
            vulns.append({"type":"备份文件泄露", "severity":"High", "description":"可下载备份/源码/数据库文件", "remediation":"删除Web目录下备份文件，定期清理"})
        if "phpinfo" in pl and ("php version" in cl or "phpinfo()" in cl):
            vulns.append({"type":"phpinfo泄露", "severity":"Medium", "description":"暴露PHP配置信息", "remediation":"删除phpinfo文件"})
        if "server-status" in pl and ("apache server status" in cl or "server uptime" in cl):
            vulns.append({"type":"Apache状态页暴露", "severity":"Medium", "description":"可查看服务器状态", "remediation":"禁止访问server-status"})
        if "web-inf/web.xml" in pl.lower() and "<web-app" in cl.lower():
            vulns.append({"type":"WEB-INF泄露", "severity":"High", "description":"Java应用配置文件泄露", "remediation":"禁止直接访问WEB-INF目录"})
        return vulns

    def scan_directories(self, base_url=None):
        """路径爆破。base_url=None时扫描主目标，否则扫描指定端口（实现IP+端口+路径找登录页）"""
        scan_url = base_url or self.clean_url
        if base_url:
            self.logger.raw("\n" + "="*30 + f" 路径爆破: {base_url} " + "="*30)
        else:
            self.logger.raw("\n" + "="*30 + " 路径爆破与漏洞验证 " + "="*30)
        path_dict, _ = load_path_dictionary()
        total_paths = len(path_dict)
        self.logger.info(f"爆破 {total_paths} 个敏感路径...")
        # 路径扫描是静态GET探测，不触发登录防护/WAF——完全跳过速率限制器
        # 用独立的fast_session：无rate_limiter.wait()、短timeout，避免被超时拖慢
        fast_session = create_secure_session(
            verify_ssl=not self.args.insecure,
            timeout=3,  # 路径扫描3秒足够，不存在的不用等8秒
            retries=0,  # 路径扫描不重试，失败就跳过
            proxy_pool=self.proxy_pool,
            rate_limiter=None,  # 关键：路径扫描不限速
            random_ua=RANDOM_UA,
            custom_headers=HEADERS
        )
        self.logger.info(f"路径扫描模式：无速率限制 + {self.args.threads}线程 + 3s超时（路径扫描不会触发WAF登录防护）")

        # 通配404检测：对新端口单独检测（每个端口的404特征不同，不能复用主目标的）
        port_wildcard = False
        port_wildcard_content = ""
        port_wildcard_len = -1
        port_wildcard_title = None
        if base_url:
            import uuid
            test_url = f"{scan_url}/test_nonexist_{uuid.uuid4().hex[:10]}"
            try:
                resp = fast_session.get(test_url, timeout=3, allow_redirects=False)
                port_wildcard_content = resp.text
                port_wildcard_len = len(resp.text)
                title_match = re.search(r"<title>(.*?)</title>", resp.text, re.I | re.S)
                if title_match:
                    port_wildcard_title = title_match.group(1).strip()
                if resp.status_code == 200:
                    port_wildcard = True
                    self.logger.warning(f"{base_url} 检测到通配404，启用过滤")
            except Exception:
                pass

        import threading
        import time as _time
        dprog = {"done": 0, "hits": 0, "start_ts": _time.time()}
        dlock = threading.Lock()

        def check_path(path):
            if self.cancel_token.is_cancelled():
                return None
            url = f"{scan_url}/{path.lstrip('/')}"
            try:
                resp = fast_session.get(url, timeout=3, allow_redirects=False)
                code = resp.status_code
                # 通配404过滤：主目标用self.wildcard_404，新端口用port_wildcard
                if base_url and port_wildcard:
                    if is_wildcard_404(resp, port_wildcard_content, port_wildcard_len, port_wildcard_title):
                        return None
                elif self.wildcard_404:
                    if is_wildcard_404(resp, self.wildcard_404_content, self.wildcard_404_len, self.wildcard_404_title):
                        return None
                    if code in [301,302] and resp.headers.get("Location","") == self.wildcard_404_redirect:
                        return None
                if code in [200, 403, 301, 302, 401]:
                    desc = {200:"存在", 403:"禁止访问(可能存在)", 301:"永久跳转", 302:"临时跳转", 401:"需要认证"}[code]
                    location = resp.headers.get("Location","")
                    if code in [301,302] and location:
                        desc += f" -> {location[:60]}"
                    with dlock: dprog["hits"] += 1
                    content_type = resp.headers.get("Content-Type", "")
                    return {
                        "path": url, 
                        "status": code, 
                        "description": desc, 
                        "content": resp.text[:2000] if "text" in content_type or "json" in content_type else "",
                        "content_type": content_type,
                        "content_length": len(resp.content)
                    }
            except (KeyboardInterrupt, SystemExit):
                self.cancel_token.cancel()
            except Exception:
                pass
            finally:
                with dlock:
                    dprog["done"] += 1
                    if dprog["done"] % 50 == 0 or dprog["done"] == total_paths:
                        pct = dprog["done"] * 100 // total_paths
                        elapsed = _time.time() - dprog["start_ts"]
                        qps = dprog["done"] / elapsed if elapsed > 0 else 0
                        sys.stdout.write(f"\r  [{dprog['done']}/{total_paths} {pct}%] 命中:{dprog['hits']} | QPS:{qps:.1f}  ")
                        sys.stdout.flush()
            return None

        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = [executor.submit(check_path, p) for p in path_dict]
            results = []
            try:
                for future in as_completed(futures):
                    try:
                        res = future.result(timeout=5)
                        if res:
                            results.append(res)
                    except (KeyboardInterrupt, SystemExit):
                        self.cancel_token.cancel()
                        break
                    except Exception:
                        pass
            except:
                self.cancel_token.cancel()

        print()

        for res in results:
            self.logger.success(f"命中: {res['path']} [{res['status']}] {res.get('content_type','')[:40]}")
            self.result.directories.append(res)
            if res["content"]:
                for v in self.verify_path_vuln(res["path"], res["content"]):
                    v["path"] = res["path"]
                    self.result.security_issues.append(v)
                    self.logger.warning(f"  漏洞确认: [{v['severity']}] {v['type']}")

    def detect_fingerprints(self):
        self.logger.raw("\n" + "="*30 + " 技术栈指纹识别 " + "="*30)
        detected = []
        hl = self.html.lower() if self.html else ""

        cms_patterns = {
            "WordPress": ["/wp-content/", "/wp-includes/", "wordpress"],
            "Drupal": ["drupal.settings", "drupal.js", "sites/all"],
            "Joomla": ["/media/system/js/", "joomla!", "com_content"],
            "ThinkPHP": ["thinkphp", "think", "/public/index.php"],
            "Laravel": ["laravel", "csrf-token", "_token"],
            "Django": ["csrfmiddlewaretoken", "django", "admin/"],
            "Flask": ["flask", "werkzeug", "x-powered-by: flask"],
            "Spring Boot": ["whitelabel error page", "spring", "actuator"],
            "Express": ["x-powered-by: express", "node.js"],
            "Vue.js": ["data-v-", "__vue__", "vue.min.js", "vue.runtime"],
            "React": ["reactroot", "_reactroot", "react.js", "react.min.js"],
            "Angular": ["ng-version", "angular.js", "angular.min.js"],
            "jQuery": ["jquery.min.js", "jquery.js", "jquery-"],
            "Bootstrap": ["bootstrap.min.css", "bootstrap.js", "bootstrap/"],
            "Element UI": ["element-ui", "el-", "elementui"],
            "Ant Design": ["antd", "ant-design", "ant.design"],
        }
        for name, patterns in cms_patterns.items():
            for pat in patterns:
                if pat.lower() in hl:
                    detected.append(name)
                    break

        server = self.headers.get("Server", "").lower()
        if "nginx" in server: detected.append("Nginx (Web服务器)")
        elif "apache" in server: detected.append("Apache (Web服务器)")
        elif "iis" in server: detected.append(f"IIS (Web服务器) {server}")
        elif "caddy" in server: detected.append("Caddy (Web服务器)")
        elif "tengine" in server: detected.append("Tengine (Web服务器)")
        elif not server:
            if self.behind_cdn:
                detected.append(f"{self.cdn_provider} 反向代理（隐藏Server头）")
            else:
                detected.append("Server头已隐藏")

        powered_by = self.headers.get("X-Powered-By", "").lower()
        if "php" in powered_by: detected.append(f"PHP {powered_by}")
        elif "asp.net" in powered_by: detected.append("ASP.NET")
        elif "express" in powered_by: detected.append("Express.js")

        detected = list(set(detected))
        self.result.fingerprints.extend([{"type":"Tech", "value":x} for x in detected])
        for fp in detected:
            self.logger.raw(f"  - {fp}")

        if self.protocol == "https" and self.ip:
            self.logger.raw("\n" + "="*30 + " SSL/TLS配置检查 " + "="*30)
            try:
                ctx = ssl.create_default_context() if not self.args.insecure else ssl._create_unverified_context()
                with socket.create_connection((self.ip, self.port), timeout=self.args.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        self.result.ssl_info = {
                            "protocol": ssock.version(),
                            "cipher": ssock.cipher()[0],
                            "cipher_bits": ssock.cipher()[2],
                            "cert_issuer": dict(x[0] for x in cert.get('issuer', ())).get('organizationName', 'Unknown'),
                            "cert_subject": dict(x[0] for x in cert.get('subject', ())).get('commonName', 'Unknown'),
                            "cert_expires": cert.get('notAfter', 'Unknown')
                        }
                        self.logger.success(f"协议: {ssock.version()} | 套件: {ssock.cipher()[0]} | 颁发者: {self.result.ssl_info['cert_issuer']}")
                        if "TLSv1.0" in ssock.version() or "TLSv1.1" in ssock.version() or "SSLv3" in ssock.version():
                            self.result.security_issues.append({
                                "type": "Weak TLS Version",
                                "severity": "Medium",
                                "path": self.clean_url,
                                "description": f"使用过时的TLS协议: {ssock.version()}",
                                "remediation": "升级到TLS 1.2或1.3，禁用旧协议"
                            })
            except Exception as e:
                self.logger.warning(f"SSL检查失败: {e}")

    def scan_security_headers(self):
        self.logger.raw("\n" + "="*30 + " 安全响应头检查 " + "="*30)
        if not self.headers:
            self.logger.error("无响应头，跳过")
            return
        sec_heads = {
            "X-Frame-Options":"防点击劫持", 
            "Content-Security-Policy":"防XSS和代码注入",
            "Strict-Transport-Security":"强制HTTPS防降级", 
            "X-Content-Type-Options":"防MIME嗅探",
            "Referrer-Policy":"控制Referrer泄露", 
            "Permissions-Policy":"浏览器权限控制",
            "X-XSS-Protection":"浏览器XSS过滤"
        }
        hl = {k.lower():v for k,v in self.headers.items()}
        missing_count = 0
        for h, desc in sec_heads.items():
            if h.lower() in hl:
                self.logger.success(f"已配置: {h}")
            else:
                self.logger.warning(f"缺失: {h} ({desc})")
                missing_count += 1
                self.result.security_issues.append({
                    "type": "Missing Security Header", "path": self.clean_url,
                    "description": f"缺失安全头: {h} - {desc}", "severity": "Low",
                    "remediation": f"在Web服务器配置中添加 {h} 头"
                })
        if missing_count == 0:
            self.logger.success("所有安全头已配置 ✓")
        elif missing_count <= 2:
            self.logger.info(f"缺少 {missing_count} 个安全头")
        else:
            self.logger.warning(f"缺少 {missing_count} 个安全头，建议加固")

    def extract_apis_from_js(self):
        if not self.html: return
        self.logger.raw("\n" + "="*30 + " JS动态API提取 " + "="*30)
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', self.html)
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', self.html, re.DOTALL)
        combined_js_content = "\n".join(inline_scripts) if inline_scripts else ""

        api_patterns = [
            r'["\']((?:/api/|/v\d+/|/rest/)[a-zA-Z0-9_/\-\{\}]+)["\']',
            r"""fetch\s*\(\s*["']([^"']+)["']""",
            r"""axios\.(?:get|post|put|delete|patch|request)\s*\(\s*["']([^"']+)""",
            r"""XMLHttpRequest.*?\.open\s*\(\s*["']\w+["']\s*,\s*["']([^"']+)""",
            r"""url\s*:\s*["']((?:/api/|/v\d+/)[^"']+)["']""",
            r'["\']((?:/api/|/v\d+/)[a-zA-Z0-9_/\-]*:[a-zA-Z0-9_]+)["\']',
        ]
        apis = set()

        def parse_js(js_path):
            if self.cancel_token.is_cancelled():
                return set()
            try:
                url = js_path if js_path.startswith("http") else f"{self.clean_url}{js_path if js_path.startswith('/') else '/'+js_path}"
                resp = self.session.get(url, timeout=self.args.timeout)
                content = resp.text
                found = set()
                for pat in api_patterns:
                    found.update(re.findall(pat, content))
                return found
            except (KeyboardInterrupt, SystemExit):
                raise
            except:
                return set()

        if js_urls or inline_scripts:
            self.logger.info(f"发现 {len(js_urls)} 个外部JS + {len(inline_scripts)} 个内联脚本")
            with ThreadPoolExecutor(max_workers=min(10, self.args.threads)) as executor:
                futures = [executor.submit(parse_js, u) for u in js_urls[:30]]
                for future in as_completed(futures):
                    try:
                        res = future.result(timeout=5)
                        apis.update(res)
                    except:
                        pass

            for pat in api_patterns:
                apis.update(re.findall(pat, combined_js_content))

        if apis:
            self.logger.success(f"提取到 {len(apis)} 个API路径")
            for api in sorted(apis):
                self.result.api_endpoints.append({"path": api, "source": "JS提取"})
                self.logger.raw(f"  - {api}")
        else:
            self.logger.info("未提取到API路径")

    def get_result_dict(self):
        self.result.scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.rate_limiter:
            self.result.rate_limit_stats = {
                "final_delay": self.rate_limiter.get_current_delay(),
                "min_delay": self.rate_limiter.min_delay,
                "max_delay": self.rate_limiter.max_delay
            }
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
            "security_issues": self.result.security_issues,
            "scan_config": {
                "threads": self.args.threads,
                "timeout": self.args.timeout,
                "verify_ssl": not self.args.insecure,
                "proxy_enabled": self.proxy_pool is not None and len(self.proxy_pool) > 0,
                "proxy_count": self.result.proxy_used,
                "rate_limit_enabled": self.rate_limiter is not None
            },
            "rate_limit_stats": self.result.rate_limit_stats
        }

def main():
    parser = argparse.ArgumentParser(description="bee-py 资产测绘引擎 v3.0")
    parser.add_argument("target", nargs="?", help="目标URL (如: https://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=THREAD_COUNT, help=f"线程数 (默认: {THREAD_COUNT})")
    parser.add_argument("-T", "--timeout", type=int, default=TIMEOUT, help=f"请求超时秒数 (默认: {TIMEOUT})")
    parser.add_argument("-k", "--insecure", action="store_true", help="禁用SSL证书验证 (不推荐)")
    parser.add_argument("-p", "--proxy-file", help="代理IP列表文件路径 (每行一个代理，如: http://user:pass@host:port)")
    
    # 速率模式选择
    speed_group = parser.add_mutually_exclusive_group()
    speed_group.add_argument("--fast", action="store_true", help="极速模式：高并发高速扫描，适合内网/授权测试，速度快但可能被封")
    speed_group.add_argument("--safe", action="store_true", help="安全模式：低并发慢速扫描，适合外网目标，不易被封")
    speed_group.add_argument("--no-rate-limit", action="store_true", help="禁用智能速率限制 (不推荐，极易被WAF封禁)")
    
    parser.add_argument("--delay", type=float, default=INITIAL_DELAY, help=f"初始请求间隔秒 (默认: {INITIAL_DELAY})")
    parser.add_argument("--min-delay", type=float, default=MIN_DELAY, help=f"最小请求间隔秒 (默认: {MIN_DELAY})")
    parser.add_argument("--max-delay", type=float, default=MAX_DELAY, help=f"最大请求间隔秒 (默认: {MAX_DELAY})")
    parser.add_argument("--no-dict-update", action="store_true", help="启动时不检查字典更新")
    parser.add_argument("--no-subdomain", action="store_true", help="跳过敏捷域名扫描")
    parser.add_argument("--no-port-scan", action="store_true", help="跳过端口扫描")
    parser.add_argument("--full-scan", "--full", action="store_true", dest="full_scan", help="完整扫描模式 (自动运行所有漏洞利用模块)")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logger = Logger()

    if not args.target:
        logger.error("未指定目标地址!")
        print(f"\n用法: python saomiao.py <URL> [选项]")
        print(f"示例: python saomiao.py https://example.com --fast --full")
        print(f"      python saomiao.py example.com --safe -p proxies.txt")
        parser.print_help()
        sys.exit(1)

    target = args.target
    if not target.startswith("http"):
        target = "https://" + target

    if not validate_target_url(target):
        logger.error(f"无效的目标URL: {target}")
        sys.exit(1)

    args.rate_limit = not args.no_rate_limit
    
    # 根据速度模式调整参数
    args.rate_preset = "normal"
    if args.fast:
        args.rate_preset = "fast"
        args.threads = max(args.threads, 100)
        args.delay = min(args.delay, 0.02)
        logger.info("⚡ 极速模式已启用：100+线程猛爆破")
    elif args.safe:
        args.rate_preset = "safe"
        args.threads = min(args.threads, 20)
        args.delay = max(args.delay, 0.2)
        logger.info("🛡️  安全模式已启用：低并发慢速扫描")

    print(f"""{Colors.RED}{Colors.BOLD}
   ███████  █████  ██████  ███    ███ ██  █████  ██████  
   ██      ██   ██ ██   ██ ████  ████ ██ ██   ██ ██   ██ 
   ███████ ███████ ██████  ██ ████ ██ ██ ███████ ██████  
        ██ ██   ██ ██   ██ ██  ██  ██ ██ ██   ██ ██   ██ 
   ███████ ██   ██ ██   ██ ██      ██ ██ ██   ██ ██   ██ 
                    bee-py · 资产测绘引擎 v3.0
{Colors.RESET}
目标: {target}
线程: {args.threads} | 超时: {args.timeout}s | SSL验证: {'关闭' if args.insecure else '开启'}
速率限制: {'启用' if args.rate_limit else '禁用'} | 代理: {'已配置' if args.proxy_file or os.path.exists(PROXY_FILE) else '未使用'}
""")

    if AUTO_UPDATE_DICTS and not args.no_dict_update:
        logger.info("检查字典更新...")
        update_result = check_dict_updates(auto_update=True)
        if update_result["updated"] > 0:
            logger.success(f"字典更新完成: 更新{update_result['updated']}个")
        elif update_result["failed"] > 0:
            logger.warning(f"字典更新失败: {update_result['failed']}个")

    scanner = AdvancedReconScanner(target, logger, args)
    
    if not args.no_subdomain:
        scanner.scan_subdomains()
    if not args.no_port_scan:
        scanner.scan_ports()
    # 1. 先扫描主目标的路径
    scanner.scan_directories()
    # 2. 对端口扫描发现的其他HTTP端口也做路径扫描（实现IP+端口+路径 找各端口后台登录页）
    http_ports_scanned = set()
    main_port = scanner.port
    for p in scanner.result.ports:
        port = p.get("port")
        if not port or port == main_port or port in http_ports_scanned:
            continue
        service = (p.get("service") or "").lower()
        # 只对HTTP类服务端口做路径扫描（避免对SSH/MySQL等非HTTP端口发GET请求）
        if port in [80, 443, 8000, 8080, 8443, 8888, 888, 8090, 7001, 7002, 9000, 9090, 10000, 2082, 2083, 2086, 2087, 2222, 88] or "http" in service:
            proto = "https" if port in [443, 8443, 2087] else "http"
            port_url = f"{proto}://{scanner.ip}:{port}"
            scanner.logger.info(f"发现HTTP端口 {port}，自动扫描其后台路径: {port_url}")
            scanner.scan_directories(base_url=port_url)
            http_ports_scanned.add(port)
    scanner.detect_fingerprints()
    scanner.scan_security_headers()
    scanner.extract_apis_from_js()

    host = sanitize_domain(scanner.domain)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = os.path.join(OUTPUT_DIR, f"scan_{host}_{ts}.json")
    
    result_dict = scanner.get_result_dict()
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(result_dict, f, ensure_ascii=False, indent=2)
    
    logger.raw("\n" + "="*60)
    logger.success(f"扫描完成! 结果已保存至: {json_file}")
    
    total_vulns = len([i for i in result_dict["security_issues"] if i["severity"] in ["Critical", "High"]])
    if total_vulns > 0:
        logger.warning(f"发现 {total_vulns} 个高危/严重漏洞!")
    
    if args.full_scan:
        logger.info(f"全自动模式：自动启动调度台运行所有漏洞利用工具...")
        import subprocess
        cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "diaodu.py"), "--auto"]
        if args.proxy_file:
            cmd.extend(["-p", args.proxy_file])
        if args.no_rate_limit:
            cmd.append("--no-rate-limit")
        subprocess.run(cmd)
    else:
        logger.info(f"运行 python diaodu.py 打开调度台选择漏洞利用工具")
    return json_file

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] 用户中断扫描 — 已完成的结果已保存{Colors.RESET}")
        sys.exit(0)
