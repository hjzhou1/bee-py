#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xss.py - XSS 跨站脚本检测工具模块
由调度系统调用，对发现的Web登录页/搜索页进行反射型/DOM型XSS检测
"""

import os
import json
import re
import datetime
import subprocess
import urllib.parse
from itertools import product

import requests

from tools import RESULTS_BASE

# ==================== 工具接口变量 ====================
TOOL_NAME = "XSS 跨站脚本检测"
TOOL_ID = "xss"
TOOL_DESC = "对发现的Web登录页/搜索页进行反射型/DOM型XSS检测"
TOOL_CATEGORY = "injection"

# ==================== 配置区 ====================
TIMEOUT = 10
VERIFY_SSL = False

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "close",
}

# 内置 XSS 测试payload（不做实际 JS 执行，只检测反射）
TEST_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg/onload=alert(1)>",
    "javascript:alert(1)",
    '"><body onload=alert(1)>',
]

# 需要关注的目标页面关键词
TARGET_PAGE_PATTERNS = [
    "login", "signin", "signup", "register", "search",
    "contact", "profile", "feedback", "comment", "submit",
    "form", "query", "find", "filter", "q=", "s="
]

# 排除的无意义文件后缀
IGNORE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".css", ".js",
    ".woff", ".ttf", ".svg", ".ico", ".pdf", ".zip", ".tar"
)


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


# ==================== 1. 页面发现模块 ====================
def _is_target_page(path):
    """判断路径是否匹配 login/search/register/contact/profile/feedback 等模式"""
    path_lower = path.lower()

    if path_lower.endswith(IGNORE_EXTENSIONS):
        return False

    if any(kw in path_lower for kw in TARGET_PAGE_PATTERNS):
        return True

    return False


def _infer_params_from_path(path, html_content="", scan_result=None):
    """从 URL 路径 / HTML 表单 / 已有参数推断可测试的参数名"""
    params = set()

    # 1. 从 URL 本身提取已有的 query 参数
    parsed = urllib.parse.urlparse(path)
    query = urllib.parse.parse_qs(parsed.query)
    for key in query:
        params.add(key)

    # 2. 从 HTML 中匹配 <form>/<input> 元素
    if html_content:
        input_matches = re.findall(r'<input[^>]+name=["\']?(\w+)["\']?', html_content, re.IGNORECASE)
        for m in input_matches:
            params.add(m)

    # 3. 根据不同页面类型补充推测参数
    path_lower = path.lower()
    heuristic_table = {
        "login": ["username", "user", "email", "passwd", "password", "token"],
        "signin": ["username", "user", "email", "passwd", "password", "token"],
        "signup": ["username", "user", "email", "passwd", "password"],
        "register": ["username", "user", "email", "passwd", "password"],
        "search": ["q", "query", "s", "keyword", "k", "search"],
        "contact": ["name", "email", "subject", "message"],
        "profile": ["id", "user", "username", "page"],
        "feedback": ["name", "email", "comment", "message", "rating"],
        "comment": ["name", "email", "comment", "text", "message"],
        "submit": ["name", "email", "message", "content"],
        "form": ["name", "email", "message", "text"],
        "query": ["q", "query", "id", "key"],
        "find": ["q", "query", "search"],
        "filter": ["q", "type", "category", "sort"],
        "q=":  ["q", "query"],
        "s=":  ["s", "search"],
    }

    for keyword, candidate_params in heuristic_table.items():
        if keyword in path_lower:
            for p in candidate_params:
                params.add(p)

    return list(params)


def _build_target_urls(scan_result, base_url, domain):
    """从扫描结果的 directories 中构建待测试的目标 URL 列表"""
    target_urls = []
    directories = scan_result.get("directories", [])
    seen = set()

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

        params = _infer_params_from_path(path)
        if not params:
            params = ["q"]

        target_urls.append({
            "url": full_url,
            "path": path,
            "params": params,
        })

    logger.info(f"从 {len(directories)} 个目录项中筛选出 {len(target_urls)} 个可疑页面")
    for t in target_urls:
        logger.raw(f"  [{','.join(t['params'][:4])}] {t['path']}")

    return target_urls


# ==================== 2. XSStrike 集成模块 ====================
def _check_xsstrike():
    """检测 XSStrike 是否可用，返回可执行命令路径或 None"""
    # 搜索常见安装位置
    candidates = [
        "xsstrike",
        "XSStrike/xsstrike.py",
        os.path.expanduser("~/XSStrike/xsstrike.py"),
        os.path.expanduser("~/tools/XSStrike/xsstrike.py"),
    ]

    for candidate in candidates:
        try:
            result = subprocess.run(
                [candidate, "--help" if candidate == "xsstrike" else candidate],
                capture_output=True, text=True, timeout=5,
                cwd=os.path.dirname(os.path.abspath(candidate)) if "/" in candidate else None
            )
            return candidate
        except Exception:
            pass

    return None


def _xsstrike_detect(target_urls, base_url, domain):
    """尝试通过 XSStrike 进行检测"""
    findings = []
    errors = []

    xsstrike_cmd = _check_xsstrike()
    if not xsstrike_cmd:
        errors.append("XSStrike 未安装或不可用，回退到内置检测")
        return findings, errors

    logger.success(f"XSStrike 可用: {xsstrike_cmd}")

    for target in target_urls:
        url = target["url"]
        logger.info(f"XSStrike 检测: {url}")
        try:
            # XSStrike 输出是终端富文本，这里退化为静默模式尝试
            proc = subprocess.run(
                [xsstrike_cmd, "-u", url, "--console-log-level", "ERROR"],
                capture_output=True, text=True, timeout=120,
                cwd=os.path.dirname(os.path.abspath(xsstrike_cmd)) if "/" in xsstrike_cmd else None
            )
            stdout = proc.stdout

            # 解析 XSStrike 输出中的发现
            for line in stdout.splitlines():
                for marker in ["Payload:", "Vulnerable", "Reflected", "reflect"]:
                    if marker.lower() in line.lower():
                        findings.append({
                            "url": url,
                            "param": "?",
                            "payload": "XSStrike detected",
                            "evidence": line.strip()[:200],
                        })
                        break
        except subprocess.TimeoutExpired:
            logger.warning(f"XSStrike 超时: {url}")
            errors.append(f"XSStrike 超时: {url}")
        except Exception as e:
            logger.warning(f"XSStrike 异常: {e}")
            errors.append(f"XSStrike 异常: {url} -> {e}")

    return findings, errors


# ==================== 3. 内置反射检测模块 ====================
def _check_reflection(html_response, payload):
    """检测 payload 是否在 HTML 响应中未转义出现"""
    if payload in html_response:
        return True

    # 部分反射：实体编码检测
    # 如果 payload 中 < > 被转成 &lt; &gt; 说明已被防御
    raw_check = payload.strip("'\"")
    if raw_check in html_response:
        return True

    return False


def _analyze_reflection_context(html_response, payload):
    """分析 payload 在 HTML 中的上下文，提供更详细的 evidence"""
    index = html_response.find(payload)
    if index == -1:
        return "payload not reflected"

    # 取反射点前后共 200 字符
    start = max(0, index - 80)
    end = min(len(html_response), index + len(payload) + 80)
    snippet = html_response[start:end]

    # 分析上下文
    if re.search(r'<script[^>]*>' + re.escape(snippet.split(payload)[0][-5:]), html_response[:index]):
        context = "script context"
    elif "onerror=" in snippet or "onload=" in snippet:
        context = "event handler"
    elif 'href="' in snippet or "href='" in snippet:
        context = "attribute (href)"
    else:
        context = "html body"

    return f"[{context}] {snippet[:200]}"


def _basic_xss_detect(target_urls, base_url, domain):
    """自实现的基本反射型 XSS 检测"""
    findings = []
    errors = []
    session = requests.Session()
    session.headers.update(HEADERS)
    session.verify = VERIFY_SSL

    for target in target_urls:
        url = target["url"]
        params = target["params"]

        logger.info(f"检测: {target['path']} (参数: {params[:5]})")

        for param, payload in product(params, TEST_PAYLOADS):
            try:
                test_url = urllib.parse.urljoin(base_url, target["path"])

                # 构造请求，payload 放在指定参数中
                resp = session.get(
                    test_url,
                    params={**{p: "1" for p in params}, param: payload},
                    timeout=TIMEOUT,
                    allow_redirects=True,
                )

                resp_text = resp.text

            except requests.exceptions.Timeout:
                logger.warning(f"超时: {test_url}?{param}={urllib.parse.quote(payload)}")
                continue
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"连接失败: {test_url} -> {e}")
                continue
            except Exception as e:
                logger.warning(f"请求异常: {test_url} -> {e}")
                errors.append(f"{test_url} -> {e}")
                continue

            if _check_reflection(resp_text, payload):
                evidence = _analyze_reflection_context(resp_text, payload)
                logger.success(f"疑似XSS: {test_url}?{param}={payload}")

                findings.append({
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "evidence": evidence,
                })
                # 同一 URL 发现一个就够了，跳到下一个目标
                break

    return findings, errors


# ==================== 4. 工具入口函数 ====================
def execute(scan_result, target_info):
    """
    执行 XSS 跨站脚本检测。

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

    logger.info(f"=== XSS 检测开始: {base_url} ===")

    # 1. 从扫描结果中找到相关 Web 页面
    target_urls = _build_target_urls(scan_result, base_url, domain)

    if not target_urls:
        logger.info("未发现与 XSS 检测相关的输入页面（login/search/register/contact/profile/feedback）")
        return {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "failed",
            "summary": "未发现可检测的输入页面",
            "targets_tested": [],
            "findings": [],
            "suggestion": "如需深度检测，请安装 XSStrike: git clone https://github.com/s0md3v/XSStrike.git",
            "errors": ["扫描结果中未发现 login/search/register/contact/profile/feedback 页面"]
        }

    # 2. 检查并尝试 XSStrike（开源工具优先）
    xsstrike_available = False
    try:
        from tools.deps import ensure_dep, check_dep
        xsstrike_available, _ = check_dep("xsstrike")
        if not xsstrike_available:
            logger.info("XSStrike 未安装，自动拉取…")
            xsstrike_available = ensure_dep("xsstrike", auto=True)
    except ImportError:
        pass

    if xsstrike_available:
        logger.success("XSStrike 已就绪，优先使用")
    xsstrike_findings, xsstrike_errors = _xsstrike_detect(target_urls, base_url, domain)
    findings.extend(xsstrike_findings)
    errors.extend(xsstrike_errors)

    # 3. 如果 XSStrike 不可用或无结果，用内置基本检测
    if not findings:
        logger.info("XSStrike 无结果，使用内置反射型检测")
        basic_findings, basic_errors = _basic_xss_detect(target_urls, base_url, domain)
        findings.extend(basic_findings)
        errors.extend(basic_errors)

    # 4. 构建结果
    targets_tested = [
        {"url": t["url"], "params": t["params"]}
        for t in target_urls
    ]

    if findings:
        status = "success"
        summary = f"检测 {len(target_urls)} 个页面，发现 {len(findings)} 处疑似XSS"
    elif errors:
        status = "partial"
        summary = f"检测 {len(target_urls)} 个页面，{len(errors)} 个错误，未确认XSS"
    else:
        status = "success"
        summary = "未发现XSS"

    logger.raw("\n" + "=" * 60)
    if findings:
        logger.success(summary)
        for f in findings:
            logger.raw(f"  [{f['param']}] {f['url']} | payload: {f['payload'][:40]}")
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
        "suggestion": "如需深度检测，请安装 XSStrike: git clone https://github.com/s0md3v/XSStrike.git",
        "errors": errors,
    }

    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    logger.info(f"结果已保存: {out_file}")
    return result
