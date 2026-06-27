#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cve_version.py - CVE 版本漏洞比对工具模块
由调度系统调用，基于指纹识别结果查询已知 CVE 漏洞库
"""

import os
import json
import re
import datetime

from tools import RESULTS_BASE

# ==================== 工具接口变量 ====================
TOOL_NAME = "CVE 版本漏洞比对"
TOOL_ID = "cve_version"
TOOL_DESC = "基于指纹识别结果查询已知CVE漏洞库"
TOOL_CATEGORY = "version"

# ==================== 颜色与日志 ====================
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class Logger:
    def info(self, msg):
        print(f"{Colors.BLUE}[INFO] {msg}{Colors.RESET}")

    def success(self, msg):
        print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")

    def warning(self, msg):
        print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")

    def error(self, msg):
        print(f"{Colors.RED}[-] {msg}{Colors.RESET}")

    def raw(self, msg):
        print(msg)


logger = Logger()


# ==================== 内嵌 CVE 漏洞库 ====================
CVE_DATABASE = [
    # === Nginx ===
    {
        "product": "nginx",
        "version_pattern": r"(?:nginx|Nginx)\s+(\d+\.\d+\.\d+(?:\.\d+)?)",
        "cve": "CVE-2017-7529",
        "condition": "<1.13.3",
        "severity": "Medium",
        "description": "Nginx 整数溢出漏洞，允许远程攻击者通过特制请求读取敏感内存信息，泄露后端数据或凭据。",
        "cvss": 7.5,
    },
    {
        "product": "nginx",
        "version_pattern": r"(?:nginx|Nginx)\s+(\d+\.\d+\.\d+(?:\.\d+)?)",
        "cve": "CVE-2013-2028",
        "condition": "<1.4.0",
        "severity": "High",
        "description": "Nginx 栈缓冲区溢出漏洞（chunked transfer encoding 处理缺陷），远程攻击者可执行任意代码。",
        "cvss": 7.5,
    },
    {
        "product": "nginx",
        "version_pattern": r"(?:nginx|Nginx)\s+(\d+\.\d+\.\d+(?:\.\d+)?)",
        "cve": "CVE-2017-20005",
        "condition": "<1.13.6",
        "severity": "Medium",
        "description": "Nginx 范围过滤模块整数溢出，允许客户端构造请求导致 worker 进程内存泄漏。",
        "cvss": 5.3,
    },
    # === Apache ===
    {
        "product": "apache",
        "version_pattern": r"(?:Apache|apache)\/(\d+\.\d+\.\d+)",
        "cve": "CVE-2021-41773",
        "condition": "<2.4.49",
        "severity": "High",
        "description": "Apache HTTP Server 路径遍历漏洞（于 2.4.49 引入，2.4.51 修复），允许远程攻击者访问受限资源，结合 CGI 可导致 RCE。",
        "cvss": 7.5,
    },
    {
        "product": "apache",
        "version_pattern": r"(?:Apache|apache)\/(\d+\.\d+\.\d+)",
        "cve": "CVE-2021-42013",
        "condition": "<2.4.51",
        "severity": "Critical",
        "description": "Apache HTTP Server 路径遍历与远程代码执行漏洞，CVE-2021-41773 的不完全修复绕过，可导致 RCE。",
        "cvss": 9.8,
    },
    {
        "product": "apache",
        "version_pattern": r"(?:Apache|apache)\/(\d+\.\d+\.\d+)",
        "cve": "CVE-2019-0211",
        "condition": "<2.4.39",
        "severity": "High",
        "description": "Apache HTTP Server MPM event 模块中低权限子进程以 root 权限执行任意代码（本地提权）。",
        "cvss": 7.8,
    },
    # === OpenSSL ===
    {
        "product": "openssl",
        "version_pattern": r"(?:OpenSSL|openssl)\s*\/?\s*(\d+\.\d+\.\d+[a-z]?)",
        "cve": "CVE-2014-0160",
        "condition": "<1.0.1g",
        "severity": "Critical",
        "description": "OpenSSL Heartbleed（心脏滴血）漏洞，允许远程攻击者读取服务器内存中的敏感信息（私钥、会话凭据等）。",
        "cvss": 9.4,
    },
    {
        "product": "openssl",
        "version_pattern": r"(?:OpenSSL|openssl)\s*\/?\s*(\d+\.\d+\.\d+[a-z]?)",
        "cve": "CVE-2014-0224",
        "condition": "<1.0.1h",
        "severity": "High",
        "description": "OpenSSL CCS 注入漏洞，允许中间人攻击者解密/伪造 SSL/TLS 流量。",
        "cvss": 7.4,
    },
    {
        "product": "openssl",
        "version_pattern": r"(?:OpenSSL|openssl)\s*\/?\s*(\d+\.\d+\.\d+[a-z]?)",
        "cve": "CVE-2022-3786",
        "condition": "<3.0.7",
        "severity": "High",
        "description": "OpenSSL X.509 邮件地址变量长度缓冲区溢出，可导致拒绝服务或远程代码执行。",
        "cvss": 7.5,
    },
    # === WordPress ===
    {
        "product": "wordpress",
        "version_pattern": r"(?:WordPress|wordpress)\s+(\d+\.\d+(?:\.\d+)?)",
        "cve": "CVE-2017-5487",
        "condition": "<4.7.1",
        "severity": "Medium",
        "description": "WordPress REST API 用户枚举漏洞，未认证用户可通过 /wp-json/wp/v2/users/ 获取所有用户的用户名列表。",
        "cvss": 5.3,
    },
    {
        "product": "wordpress",
        "version_pattern": r"(?:WordPress|wordpress)\s+(\d+\.\d+(?:\.\d+)?)",
        "cve": "CVE-2019-8943",
        "condition": "<5.0.1",
        "severity": "High",
        "description": "WordPress 图像处理模块路径遍历漏洞（Crop-image），已认证用户可通过裁剪功能实现任意文件读取和写入。",
        "cvss": 8.8,
    },
    # === PHP ===
    {
        "product": "php",
        "version_pattern": r"(?:PHP|php)\s*\/?\s*(\d+\.\d+\.\d+)",
        "cve": "CVE-2019-11043",
        "condition": "<7.4.0",
        "severity": "Critical",
        "description": "PHP-FPM 远程代码执行漏洞（php-fpm underflow），通过构造特殊 FastCGI 请求在 nginx+php-fpm 环境中执行任意代码。",
        "cvss": 9.8,
    },
    {
        "product": "php",
        "version_pattern": r"(?:PHP|php)\s*\/?\s*(\d+\.\d+\.\d+)",
        "cve": "CVE-2018-19518",
        "condition": "<7.3.0",
        "severity": "High",
        "description": "PHP imap_open() 使用不安全的默认邮箱名构造，可被本地攻击者利用实现远程代码执行。",
        "cvss": 8.1,
    },
    # === MySQL ===
    {
        "product": "mysql",
        "version_pattern": r"(?:MySQL|mysql|MariaDB|mariadb)[\s\/]*(\d+\.\d+\.\d+)",
        "cve": "CVE-2012-5611",
        "condition": "<5.6.0",
        "severity": "Medium",
        "description": "MySQL 栈溢出漏洞（COM_FIELD_LIST 命令处理），已认证用户可通过该漏洞导致服务崩溃或执行任意代码。",
        "cvss": 6.5,
    },
    {
        "product": "mysql",
        "version_pattern": r"(?:MySQL|mysql|MariaDB|mariadb)[\s\/]*(\d+\.\d+\.\d+)",
        "cve": "CVE-2016-6662",
        "condition": "<5.7.16",
        "severity": "Critical",
        "description": "MySQL 远程代码执行漏洞，攻击者通过设置 malicious my.cnf 参数并以 root 权限写入配置文件，获得 root shell。",
        "cvss": 9.8,
    },
    # === PostgreSQL ===
    {
        "product": "postgresql",
        "version_pattern": r"(?:PostgreSQL|postgresql|Postgres|postgres)[\s\/]*(\d+\.\d+(?:\.\d+)?)",
        "cve": "CVE-2019-9193",
        "condition": "<11.3",
        "severity": "High",
        "description": "PostgreSQL COPY TO/FROM PROGRAM 功能可被已认证用户利用实现命令执行。",
        "cvss": 7.2,
    },
    {
        "product": "postgresql",
        "version_pattern": r"(?:PostgreSQL|postgresql|Postgres|postgres)[\s\/]*(\d+\.\d+(?:\.\d+)?)",
        "cve": "CVE-2018-1058",
        "condition": "<10.3",
        "severity": "Medium",
        "description": "PostgreSQL search_path 控制不当导致已认证用户可通过创建同名函数执行任意代码。",
        "cvss": 6.5,
    },
    # === Tomcat ===
    {
        "product": "tomcat",
        "version_pattern": r"(?:Apache Tomcat|Tomcat|Apache-Coyote|Apache Tomcat/|tomcat)\/?\s*(\d+\.\d+\.\d+)",
        "cve": "CVE-2017-12617",
        "condition": "<9.0.1",
        "severity": "High",
        "description": "Apache Tomcat 远程代码执行漏洞（PUT 方法缺陷），配置了 read-only=false 的 Tomcat 可被上传 JSP Webshell。",
        "cvss": 8.1,
    },
    # === Redis ===
    {
        "product": "redis",
        "version_pattern": r"(?:Redis|redis)\s+(\d+\.\d+\.\d+)",
        "cve": "CVE-2015-4335",
        "condition": "<3.0.2",
        "severity": "Critical",
        "description": "Redis Lua 沙箱逃逸漏洞，已认证用户可通过恶意 Lua 脚本在服务器上执行任意代码。",
        "cvss": 9.0,
    },
    # === PHPMyAdmin ===
    {
        "product": "phpmyadmin",
        "version_pattern": r"(?:phpMyAdmin|phpmyadmin)\s+(\d+\.\d+\.\d+)",
        "cve": "CVE-2018-12613",
        "condition": "<4.8.2",
        "severity": "Medium",
        "description": "phpMyAdmin 文件包含漏洞，已认证用户可利用 index.php target 参数实现远程代码执行。",
        "cvss": 6.5,
    },
]


# ==================== 版本解析模块 ====================
def _parse_version(version_string):
    """解析版本字符串为 (major, minor, patch) 元组"""
    parts = re.findall(r'(\d+)', version_string)
    result = []
    for p in parts[:3]:
        result.append(int(p))
    while len(result) < 3:
        result.append(0)
    return tuple(result)


def _version_lt(version_string, target_string):
    """判断 version_string 是否小于 target_string"""
    v1 = _parse_version(version_string)
    v2 = _parse_version(target_string)
    return v1 < v2


def _extract_version_candidates(text, pattern):
    """从文本中提取匹配模式的版本号"""
    candidates = []
    for match in re.finditer(pattern, text, re.IGNORECASE):
        candidates.append({
            "full_match": match.group(0),
            "version": match.group(1),
        })
    return candidates


# ==================== CVE 匹配模块 ====================
def _match_cve(fingerprint_text, fingerprint_type="fingerprint"):
    """将指纹文本与 CVE 数据库匹配"""
    matches = []

    for cve_entry in CVE_DATABASE:
        product = cve_entry["product"]
        pattern = cve_entry["version_pattern"]
        condition = cve_entry["condition"]

        candidates = _extract_version_candidates(fingerprint_text, pattern)
        for c in candidates:
            version = c["version"]

            # 解析条件并比对
            condition_match = re.match(r'<(\d+\.\d+\.\d+(?:\.\d+)?[a-z]?)', condition)
            if condition_match:
                max_version = condition_match.group(1)
                if _version_lt(version, max_version):
                    matches.append({
                        "fingerprint": fingerprint_text.strip(),
                        "fingerprint_type": fingerprint_type,
                        "product": product,
                        "detected_version": version,
                        "cve": cve_entry["cve"],
                        "severity": cve_entry["severity"],
                        "description": cve_entry["description"],
                        "cvss": cve_entry["cvss"],
                        "condition": condition,
                    })
                    logger.warning(f"[{cve_entry['severity']}] {fingerprint_text.strip()} -> {cve_entry['cve']} ({cve_entry['description'][:60]}...)")

    return matches


# ==================== 指纹提取模块 ====================
def _extract_fingerprints(scan_result):
    """从扫描结果中提取指纹和版本信息"""
    fingerprints = []

    # 1. 从 fingerprints 字段提取
    scan_fingerprints = scan_result.get("fingerprints", [])
    for fp in scan_fingerprints:
        if isinstance(fp, str):
            fingerprints.append({
                "text": fp,
                "type": "fingerprint",
            })
        elif isinstance(fp, dict):
            text = fp.get("value", fp.get("text", fp.get("raw", "")))
            fp_type = fp.get("type", "fingerprint")
            if text:
                fingerprints.append({
                    "text": str(text),
                    "type": fp_type,
                })

    # 2. 从 ports 字段的 version 提取
    ports = scan_result.get("ports", [])
    for p in ports:
        version = p.get("version", "")
        service = p.get("service", "")
        if version and service:
            f_text = f"{service} {version}"
            fingerprints.append({
                "text": f_text,
                "type": "port_version",
            })

    # 3. 从 ssl_info 提取
    ssl_info = scan_result.get("ssl_info", {})
    if ssl_info:
        if isinstance(ssl_info, dict):
            ssl_text = json.dumps(ssl_info)
        else:
            ssl_text = str(ssl_info)
        fingerprints.append({
            "text": ssl_text,
            "type": "ssl_info",
        })

    # 4. 从 HTTP 响应头提取 Server / X-Powered-By
    headers_info = scan_result.get("headers", {})
    if isinstance(headers_info, dict):
        for header_name in ["Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache"]:
            value = headers_info.get(header_name, "")
            if value:
                fingerprints.append({
                    "text": f"{header_name}: {value}",
                    "type": "http_header",
                })

    # 去重
    seen = set()
    unique_fps = []
    for fp in fingerprints:
        text_norm = fp["text"].strip().lower()
        if text_norm and text_norm not in seen:
            seen.add(text_norm)
            unique_fps.append(fp)

    logger.info(f"从扫描结果中提取到 {len(unique_fps)} 条指纹信息")
    for fp in unique_fps:
        logger.raw(f"  [{fp['type']}] {fp['text'][:100]}")

    return unique_fps


# ==================== 工具入口函数 ====================
def execute(scan_result, target_info):
    """
    执行 CVE 版本漏洞比对。

    Args:
        scan_result: dict, saomiao.py 输出的扫描结果
        target_info: dict, 包含 domain, ip, base_url

    Returns:
        dict: 标准化结果
    """
    domain = target_info.get("domain", "unknown")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logger.info(f"=== CVE 版本漏洞比对开始: {domain} ===")

    errors = []

    # 1. 提取指纹信息
    fingerprints = _extract_fingerprints(scan_result)

    if not fingerprints:
        logger.info("未发现可解析的指纹/版本信息")
        return {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "failed",
            "summary": "未发现可解析的指纹/版本信息",
            "fingerprints_found": [],
            "cve_matches": [],
            "suggestion": "建议先进行服务指纹识别扫描，获取更详细的服务版本信息。",
            "errors": ["扫描结果中未发现 fingerprint、port version 或 ssl_info 等版本信息"]
        }

    # 2. 逐个指纹与 CVE 数据库匹配
    all_matches = []
    for fp in fingerprints:
        try:
            matches = _match_cve(fp["text"], fp["type"])
            all_matches.extend(matches)
        except Exception as e:
            logger.error(f"指纹匹配出错: {fp['text'][:60]} -> {e}")
            errors.append(f"匹配异常: {fp['text'][:60]} -> {e}")

    # 3. 按严重程度排序
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_matches.sort(key=lambda x: severity_order.get(x["severity"], 99))

    # 4. 去重（同 CVE 同产品只保留一次）
    seen_cve = set()
    unique_matches = []
    for m in all_matches:
        key = (m["cve"], m["product"])
        if key not in seen_cve:
            seen_cve.add(key)
            unique_matches.append(m)

    # 5. 确定状态
    if unique_matches:
        critical_count = sum(1 for m in unique_matches if m["severity"] == "Critical")
        high_count = sum(1 for m in unique_matches if m["severity"] == "High")
        matched_count = len(unique_matches)

        status = "success"
        summary = f"发现 {matched_count} 个已知 CVE"
        if critical_count > 0:
            summary += f"，{critical_count} 个严重（Critical）"
        if high_count > 0:
            summary += f"，{high_count} 个高危（High）"

        suggestion = "建议尽快升级以下组件至最新版本："
        affected_products = list(set(m["product"] for m in unique_matches))
        suggestion += "、".join(affected_products)
    elif errors:
        status = "partial"
        summary = f"比对完成，{len(errors)} 个错误，未发现已知 CVE"
        suggestion = "建议检查指纹扫描结果是否完整"
    else:
        status = "success"
        summary = "未发现匹配的已知 CVE"
        suggestion = "当前已检测的组件版本暂未知名漏洞，建议定期更新漏洞库保持检测能力"

    # 6. 构建指纹列表输出
    fingerprints_found = [{"text": fp["text"], "type": fp["type"]} for fp in fingerprints]

    logger.raw("\n" + "=" * 60)
    if unique_matches:
        logger.success(summary)
        for m in unique_matches:
            sev_color = {
                "Critical": Colors.RED + Colors.BOLD,
                "High": Colors.RED,
                "Medium": Colors.YELLOW,
                "Low": Colors.BLUE,
            }.get(m["severity"], Colors.RESET)
            logger.raw(f"  {sev_color}[{m['severity']}]{Colors.RESET} {m['cve']} - {m['fingerprint'][:80]} | {m['description'][:80]}")
    else:
        logger.info(summary)

    # 7. 保存结果文件
    output_dir = os.path.join(RESULTS_BASE, TOOL_ID)
    os.makedirs(output_dir, exist_ok=True)
    ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(output_dir, f"{domain}_{ts_file}.json")

    result = {
        "tool": TOOL_ID,
        "target": domain,
        "time": timestamp,
        "status": status,
        "summary": summary,
        "fingerprints_found": fingerprints_found,
        "cve_matches": unique_matches,
        "suggestion": suggestion,
        "errors": errors,
    }

    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    logger.info(f"结果已保存: {out_file}")
    return result
