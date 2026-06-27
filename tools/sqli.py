#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sqli.py - SQL 注入检测工具模块
由调度系统调用，对 API 端点和登录页进行 SQL 注入检测（调用 sqlmap）
依赖: requests
"""

import os
import json
import re
import datetime
import subprocess
import urllib.parse

import requests

from tools import RESULTS_BASE

# ==================== 工具接口变量 ====================
TOOL_NAME = "SQL 注入检测"
TOOL_ID = "sqli"
TOOL_DESC = "对 API 端点和登录页进行 SQL 注入检测（调用 sqlmap）"
TOOL_CATEGORY = "injection"

# ==================== 配置区 ====================
TIMEOUT = 10
MAX_DOWNLOAD_SIZE = 10 * 1024 * 1024
VERIFY_SSL = False
SQLMAP_OUTPUT_DIR = "/tmp/sqlmap_output"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/json,*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "close",
}

# 登录/管理页面匹配关键词
LOGIN_ADMIN_PATTERNS = [
    "login", "signin", "admin", "manage", "dashboard",
    "cms", "wp-admin", "administrator", "panel", "control",
]

# 排除的无意义文件后缀
IGNORE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".css", ".js",
    ".woff", ".ttf", ".svg", ".ico", ".pdf", ".zip", ".tar"
)

# SQL 错误特征库
SQL_ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL server version",
        r"Unknown column",
        r"mysql_fetch",
        r"mysqli_fetch",
        r"You have an error in your SQL syntax",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*?ERROR",
        r"Warning.*?pg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"org\.postgresql\.util\.PSQLException",
        r"PSQLException",
        r"SQLSTATE\[",
    ],
    "MSSQL": [
        r"OLE DB.*?SQL Server",
        r"SQLServer JDBC Driver",
        r"SqlException",
        r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for ODBC Drivers",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Incorrect syntax near",
    ],
    "Oracle": [
        r"Oracle.*?Driver",
        r"Warning.*?oci_",
        r"OracleException",
        r"java\.sql\.SQLException.*?ORA-",
        r"ORA-\d{5}",
        r"Oracle error",
        r"PL/SQL:",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*?sqlite_",
        r"sqlite3\.OperationalError",
        r"unrecognized token",
    ],
    "Generic": [
        r"SQL injection",
        r"SQLi",
        r"syntax error",
        r"database error",
        r"unclosed quotation mark",
        r"ODBC Driver",
        r"JDBCException",
        r"DBD::",
    ],
}

# 基本注入测试 payload
SQL_TEST_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    '" OR "1"="1',
    '" OR "1"="1" --',
    "' OR 1=1 --",
    "') OR ('1'='1",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1 AND 1=1",
    "1 AND 1=2",
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "'; WAITFOR DELAY '00:00:05' --",
    "' OR SLEEP(5) --",
    "' OR pg_sleep(5) --",
]


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


# ==================== 通用下载器 ====================
def safe_download(url, stream=False, max_size=MAX_DOWNLOAD_SIZE):
    """带限速和异常处理的通用下载，防止内存炸弹"""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                           verify=VERIFY_SSL, stream=stream, allow_redirects=True)
        if resp.status_code != 200:
            return None
        if stream:
            chunks = []
            total = 0
            for chunk in resp.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > max_size:
                    logger.warning(f"文件过大 (>10MB)，截断: {url}")
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        else:
            if len(resp.content) > max_size:
                logger.warning(f"响应过大 (>10MB)，截断: {url}")
                return resp.content[:max_size]
            return resp.content
    except Exception as e:
        logger.warning(f"下载失败: {url} -> {e}")
        return None


# ==================== 1. 目标 URL 提取模块 ====================
def _is_target_page(path):
    """判断路径是否匹配 login/admin 等模式"""
    path_lower = path.lower()

    if path_lower.endswith(IGNORE_EXTENSIONS):
        return False

    if any(kw in path_lower for kw in LOGIN_ADMIN_PATTERNS):
        return True

    return False


def _extract_query_params(url):
    """从 URL 中提取查询参数名"""
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    return list(query.keys())


def _build_target_urls(scan_result, base_url, domain):
    """从扫描结果中构建待测试的目标 URL 列表"""
    target_urls = []
    seen = set()

    # 1. 从 api_endpoints 中提取
    api_endpoints = scan_result.get("api_endpoints", [])
    for ep in api_endpoints:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        if not url:
            continue
        full_url = urllib.parse.urljoin(base_url, url)
        if full_url in seen:
            continue
        seen.add(full_url)

        params = _extract_query_params(full_url)
        if not params:
            params = ["id", "q", "page"]
        target_urls.append({
            "url": full_url,
            "path": url,
            "params": params,
            "source": "api_endpoints",
        })

    # 2. 从 directories 中提取 login/admin 页面
    directories = scan_result.get("directories", [])
    for d in directories:
        path = d.get("path", "")
        status = d.get("status", 0)
        if status != 200:
            continue
        if not _is_target_page(path):
            continue

        full_url = urllib.parse.urljoin(base_url, path)
        if full_url in seen:
            continue
        seen.add(full_url)

        params = _extract_query_params(full_url)
        if not params:
            params = ["username", "user", "id", "q", "page", "token"]

        target_urls.append({
            "url": full_url,
            "path": path,
            "params": params,
            "source": "directories",
        })

    logger.info(f"从扫描结果中构建了 {len(target_urls)} 个 SQL 注入检测目标")
    for t in target_urls:
        logger.raw(f"  [{t['source']}] {t['path']} (参数: {t['params'][:4]})")

    return target_urls


# ==================== 2. sqlmap 集成模块 ====================
def _check_sqlmap():
    """检测 sqlmap 是否可用，返回可执行命令路径或 None"""
    # 优先用 deps.py 管理的本地版本
    try:
        from tools.deps import check_dep, ensure_dep
        available, path = check_dep("sqlmap")
        if available:
            return path
        logger.info("sqlmap 未安装，自动拉取…")
        if ensure_dep("sqlmap", auto=True):
            available, path = check_dep("sqlmap")
            if available:
                return path
    except ImportError:
        pass

    # fallback：搜索系统路径
    candidates = [
        "sqlmap", "sqlmap.py",
        os.path.expanduser("~/sqlmap/sqlmap.py"),
        "/usr/bin/sqlmap", "/usr/local/bin/sqlmap",
    ]
    for candidate in candidates:
        try:
            result = subprocess.run(
                [candidate, "--version"] if "/" not in candidate else ["python3", candidate, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return candidate
        except Exception:
            pass

    return None


def _parse_sqlmap_output(output_text):
    """解析 sqlmap 输出，提取已确认的注入点"""
    findings = []

    lines = output_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]

        # 检测参数注入点
        param_match = re.search(r"Parameter\s+['\"]([^'\"]+)['\"]\s+is\s+vulnerable", line, re.IGNORECASE)
        if not param_match:
            param_match = re.search(r"parameter\s+['\"]([^'\"]+)['\"]\s+is\s+injectable", line, re.IGNORECASE)

        if param_match:
            param = param_match.group(1)
            inject_type = "unknown"
            payload = ""
            technique = ""

            # 获取注入类型
            for j in range(i, min(i + 20, len(lines))):
                t = lines[j]
                if "Type:" in t and ("boolean-based" in t or "error-based" in t or
                                     "time-based" in t or "UNION query" in t or
                                     "stacked queries" in t):
                    inject_type = t.strip()
                elif "Payload:" in t:
                    payload = t.split("Payload:", 1)[-1].strip()[:200]
                elif "technique:" in t.lower():
                    technique = t.split(":", 1)[-1].strip()

            findings.append({
                "param": param,
                "injection_type": inject_type,
                "technique": technique,
                "payload": payload,
                "source": "sqlmap",
            })

        # 检测 "identified the following injection point(s)"
        if "identified the following injection" in line.lower():
            j = i + 1
            while j < len(lines) and j < i + 15:
                details_line = lines[j]
                place_match = re.search(r"Place:\s*(.+)", details_line, re.IGNORECASE)
                param_match2 = re.search(r"Parameter:\s*(.+)", details_line, re.IGNORECASE)
                type_match = re.search(r"Type:\s*(.+)", details_line, re.IGNORECASE)
                title_match = re.search(r"Title:\s*(.+)", details_line, re.IGNORECASE)

                if any([place_match, param_match2, type_match, title_match]):
                    param = (param_match2.group(1).strip() if param_match2 else
                            place_match.group(1).strip() if place_match else "?")
                    inject_type = type_match.group(1).strip() if type_match else "unknown"
                    title = title_match.group(1).strip() if title_match else ""
                    findings.append({
                        "param": param,
                        "injection_type": inject_type,
                        "technique": "",
                        "payload": title if title else inject_type,
                        "source": "sqlmap",
                    })
                j += 1

        i += 1

    return findings


def _sqlmap_detect(target_urls, base_url, domain):
    """通过 sqlmap 进行 SQL 注入检测"""
    findings = []
    errors = []

    sqlmap_cmd = _check_sqlmap()
    if not sqlmap_cmd:
        errors.append("sqlmap 未安装或不可用，回退到内置错误检测")
        return findings, errors

    logger.success(f"sqlmap 可用: {sqlmap_cmd}")

    for target in target_urls:
        url = target["url"]
        logger.info(f"sqlmap 检测: {url}")

        try:
            cmd = [sqlmap_cmd, "-u", url, "--batch", "--level=1", "--risk=1",
                   f"--output-dir={SQLMAP_OUTPUT_DIR}", "--flush-session"]
            if "/" not in sqlmap_cmd:
                pass
            else:
                cmd = ["python3"] + cmd

            proc = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=180,
            )
            stdout = proc.stdout

            target_findings = _parse_sqlmap_output(stdout)
            for f in target_findings:
                f["url"] = url
            findings.extend(target_findings)

            if target_findings:
                logger.success(f"sqlmap 发现 {len(target_findings)} 个注入点: {url}")
                for f in target_findings:
                    logger.raw(f"  [{f['param']}] {f['injection_type']}")

        except subprocess.TimeoutExpired:
            logger.warning(f"sqlmap 超时: {url}")
            errors.append(f"sqlmap 超时: {url}")
        except FileNotFoundError:
            logger.warning("sqlmap 命令未找到")
            errors.append("sqlmap 命令未找到")
            break
        except Exception as e:
            logger.warning(f"sqlmap 异常: {e}")
            errors.append(f"sqlmap 异常: {url} -> {e}")

    return findings, errors


# ==================== 3. 基本错误检测模块 ====================
def _check_sql_errors(response_text):
    """检测响应中是否包含 SQL 错误信息"""
    matches = []
    for db_type, patterns in SQL_ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                matches.append({
                    "db_type": db_type,
                    "pattern": pattern,
                })
    return matches


def _basic_sqli_detect(target_urls, base_url, domain):
    """自实现的基本错误型 SQL 注入检测"""
    findings = []
    errors = []
    session = requests.Session()
    session.headers.update(HEADERS)
    session.verify = VERIFY_SSL

    for target in target_urls:
        url = target["url"]
        params = target["params"]

        logger.info(f"基本检测: {target['path']} (参数: {params[:4]})")

        if not params:
            continue

        # 先用正常请求获取基准响应
        try:
            base_resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            base_text = base_resp.text
            base_len = len(base_text)
        except Exception as e:
            logger.warning(f"基准请求失败: {url} -> {e}")
            errors.append(f"{url} -> {e}")
            continue

        for param in params:
            for payload in SQL_TEST_PAYLOADS:
                try:
                    test_url = urllib.parse.urljoin(base_url, target["path"])
                    resp = session.get(
                        test_url,
                        params={param: payload},
                        timeout=TIMEOUT,
                        allow_redirects=True,
                    )

                    resp_text = resp.text

                    # 检查 SQL 错误
                    error_matches = _check_sql_errors(resp_text)
                    if error_matches:
                        db_types = list(set(m["db_type"] for m in error_matches))
                        evidence_patterns = [m["pattern"] for m in error_matches[:3]]

                        logger.success(f"疑似SQL注入: {test_url}?{param}={urllib.parse.quote(payload)} [{', '.join(db_types)}]")

                        findings.append({
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "db_type": db_types,
                            "evidence": evidence_patterns,
                            "source": "basic_error_detect",
                        })
                        break

                    # 检查响应长度异常（可能盲注成功）
                    resp_len = len(resp_text)
                    if resp_len > 0 and base_len > 0:
                        ratio = abs(resp_len - base_len) / base_len
                        if ratio > 0.3:
                            logger.warning(f"响应长度异常: {test_url}?{param}={urllib.parse.quote(payload)} ({base_len}->{resp_len}, {ratio:.0%})")

                except requests.exceptions.Timeout:
                    logger.warning(f"超时: {url}?{param}={urllib.parse.quote(payload[:30])}")
                except requests.exceptions.ConnectionError as e:
                    logger.warning(f"连接失败: {url} -> {e}")
                except Exception as e:
                    logger.warning(f"请求异常: {url} -> {e}")
                    errors.append(f"{url}?{param}= -> {e}")

    return findings, errors


# ==================== 4. 工具入口函数 ====================
def execute(scan_result, target_info):
    """
    执行 SQL 注入检测。

    Args:
        scan_result: dict, saomiao.py 输出的扫描结果
        target_info: dict, 包含 domain, ip, base_url, protocol

    Returns:
        dict: 标准化结果
    """
    domain = target_info.get("domain", "unknown")
    base_url = target_info.get("base_url", "")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not base_url:
        protocol = target_info.get("protocol", "https")
        base_url = f"{protocol}://{domain}"

    findings = []
    errors = []

    logger.info(f"=== SQL 注入检测开始: {base_url} ===")

    # 1. 构建目标 URL 列表
    target_urls = _build_target_urls(scan_result, base_url, domain)

    if not target_urls:
        logger.info("未发现可检测的 SQL 注入目标（API端点和登录/管理页面）")
        return {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "failed",
            "summary": "未发现可检测的 SQL 注入目标",
            "targets_tested": [],
            "findings": [],
            "suggestion": "确认目标是否包含 API 端点或登录/管理页面。也可以手动指定 URL 进行检测。",
            "errors": ["扫描结果中未发现 API 端点或 login/admin 页面"]
        }

    # 2. 尝试用 sqlmap 检测
    sqlmap_findings, sqlmap_errors = _sqlmap_detect(target_urls, base_url, domain)
    findings.extend(sqlmap_findings)
    errors.extend(sqlmap_errors)

    # 3. 如果 sqlmap 不可用或无结果，用内置基本检测
    if not findings:
        logger.info("sqlmap 无结果或不可用，使用内置错误型检测")
        basic_findings, basic_errors = _basic_sqli_detect(target_urls, base_url, domain)
        findings.extend(basic_findings)
        errors.extend(basic_errors)

    # 4. 构建结果
    targets_tested = [
        {"url": t["url"], "params": t["params"], "source": t["source"]}
        for t in target_urls
    ]

    if findings:
        status = "success"
        summary = f"检测 {len(target_urls)} 个目标，发现 {len(findings)} 处疑似 SQL 注入"
    elif errors:
        status = "partial"
        summary = f"检测 {len(target_urls)} 个目标，{len(errors)} 个错误，未确认 SQL 注入"
    else:
        status = "success"
        summary = "未发现 SQL 注入"

    logger.raw("\n" + "=" * 60)
    if findings:
        logger.success(summary)
        for f in findings:
            logger.raw(f"  [{f['param']}] {f['url']} | type: {f.get('injection_type', f.get('db_type', '?'))}")
    else:
        logger.info(summary)

    # 5. 保存结果文件
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
        "targets_tested": targets_tested,
        "findings": findings,
        "suggestion": "建议对疑似注入点进行手动验证或使用 sqlmap --level=3 --risk=3 进行深度扫描",
        "errors": errors,
    }

    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    logger.info(f"结果已保存: {out_file}")
    return result
