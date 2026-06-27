# -*- coding: utf-8 -*-
"""
swagger_leak.py - Swagger/OpenAPI 接口审计工具
解析 swagger.json，枚举全部 API 端点+参数
"""

import os
import json
import re
import datetime
import requests

from tools import RESULTS_BASE

TOOL_NAME = "Swagger/OpenAPI 接口审计"
TOOL_ID = "swagger_leak"
TOOL_DESC = "解析 swagger.json，枚举全部API端点+参数"
TOOL_CATEGORY = "info_leak"

TIMEOUT = 10
VERIFY_SSL = False

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "close",
}


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


def safe_download(url, stream=False, max_size=100 * 1024 * 1024):
    """带限速和异常处理的通用下载，防止内存炸弹"""
    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            verify=VERIFY_SSL,
            stream=stream,
            allow_redirects=True,
        )
        if resp.status_code != 200:
            return None
        if stream:
            chunks = []
            total = 0
            for chunk in resp.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > max_size:
                    logger.warning(f"文件过大 (>100MB)，截断: {url}")
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        else:
            if len(resp.content) > max_size:
                logger.warning(f"响应过大 (>100MB)，截断: {url}")
                return resp.content[:max_size]
            return resp.content
    except Exception as e:
        logger.warning(f"下载失败: {url} -> {e}")
        return None


def _extract_swagger_items(scan_result):
    """从扫描结果中提取 Swagger/OpenAPI 相关条目"""
    directories = scan_result.get("directories", [])
    security_issues = scan_result.get("security_issues", [])

    swagger_items = []

    for issue in security_issues:
        path = issue.get("path", "")
        itype = issue.get("type", "")
        if "Swagger" in itype or "swagger" in path.lower() or "openapi" in path.lower():
            swagger_items.append({"path": path, "source": "security_issue"})

    for d in directories:
        p = d["path"].lower()
        if d["status"] == 200 and any(x in p for x in ["swagger", "openapi"]):
            if not any(e["path"] == d["path"] for e in swagger_items):
                swagger_items.append({"path": d["path"], "source": "directory_scan"})

    return swagger_items


def execute(scan_result, target_info):
    """
    执行 Swagger/OpenAPI 接口审计

    Args:
        scan_result: saomiao.py 生成的完整扫描结果 dict
        target_info: 目标信息 {"domain": "...", "protocol": "..."}

    Returns:
        dict: 标准化结果 {tool, target, time, status, summary, errors}
    """
    domain = target_info.get("domain", "unknown")
    base_url = f"{target_info.get('protocol', 'https')}://{domain}"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    errors = []

    # 1. 提取 Swagger/OpenAPI 条目
    swagger_items = _extract_swagger_items(scan_result)
    if not swagger_items:
        return {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "failed",
            "summary": {"api_title": None, "api_version": None, "host": None,
                        "base_path": None, "total_endpoints": 0, "endpoints": [],
                        "suggestion": "未发现 Swagger/OpenAPI 相关路径"},
            "errors": ["扫描结果中未发现 Swagger/OpenAPI 相关条目"]
        }

    # 2. 区分 JSON/YAML 和 HTML 入口
    json_urls = [
        s["path"] for s in swagger_items
        if any(x in s["path"].lower() for x in [".json", ".yaml", ".yml"])
    ]
    html_urls = [
        s["path"] for s in swagger_items
        if not any(x in s["path"].lower() for x in [".json", ".yaml", ".yml"])
    ]

    # 优先 JSON/YAML 规范文件
    target_url = json_urls[0] if json_urls else html_urls[0] if html_urls else swagger_items[0]["path"]

    logger.info(f"利用 Swagger 暴露: {target_url}")

    # 3. 下载文档内容
    content = safe_download(target_url)
    if not content:
        errors.append(f"下载失败: {target_url}")
        return {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "failed",
            "summary": {"api_title": None, "api_version": None, "host": None,
                        "base_path": None, "total_endpoints": 0, "endpoints": [],
                        "swagger_url": target_url,
                        "suggestion": f"文档不可访问: {target_url}"},
            "errors": errors
        }

    text = content.decode("utf-8", errors="ignore")

    # 4. 如果不是 JSON/YAML 入口，作为 UI 页面处理
    if target_url not in json_urls:
        result = {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "partial",
            "summary": {
                "api_title": None,
                "api_version": None,
                "host": None,
                "base_path": None,
                "total_endpoints": 0,
                "endpoints": [],
                "swagger_url": target_url,
                "suggestion": (
                    f"手动访问 {target_url} 查看交互式文档，"
                    f"或尝试 {target_url.replace('swagger-ui.html', 'v3/api-docs').replace('swagger-ui/', 'swagger.json')}"
                )
            },
            "errors": ["目标为 Swagger UI 页面，非 JSON/YAML 规范文件"]
        }

        output_dir = os.path.join(RESULTS_BASE, TOOL_ID)
        os.makedirs(output_dir, exist_ok=True)
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(output_dir, f"{domain}_{ts_file}.json")
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        logger.info(f"结果已保存: {out_file}")
        return result

    # 5. 解析 Swagger/OpenAPI 规范
    endpoints = []
    api_title = None
    api_version = None
    host = None
    base_path = ""

    try:
        if target_url.endswith(".json"):
            spec = json.loads(text)
        elif target_url.endswith((".yaml", ".yml")):
            try:
                import yaml
                spec = yaml.safe_load(text)
            except ImportError:
                logger.warning("未安装 PyYAML，无法解析 YAML，回退 JSON 尝试")
                spec = json.loads(text)
        else:
            spec = json.loads(text)

        # 提取元信息
        info = spec.get("info", {})
        api_title = info.get("title", "")
        api_version = info.get("version", "")
        host = spec.get("host", "")
        base_path = spec.get("basePath", "")

        # 枚举全部 API 端点
        paths = spec.get("paths", {})
        if isinstance(paths, dict):
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                for method, details in methods.items():
                    method_upper = method.upper()
                    if method_upper not in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
                        continue

                    params = []
                    raw_params = details.get("parameters", [])
                    if isinstance(raw_params, list):
                        for p in raw_params:
                            if isinstance(p, dict):
                                params.append({
                                    "name": p.get("name", "?"),
                                    "in": p.get("in", "?"),
                                    "required": p.get("required", False),
                                    "type": p.get("type", p.get("schema", {}).get("type", "?")),
                                })

                    endpoints.append({
                        "method": method_upper,
                        "path": f"{base_path}{path}",
                        "summary": str(details.get("summary", details.get("description", "")))[:120],
                        "parameters": params,
                    })

        logger.success(f"Swagger 枚举 {len(endpoints)} 个 API 端点: {target_url}")
        for ep in endpoints[:10]:
            logger.raw(f"    {ep['method']:6} {ep['path']}")

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        errors.append(f"Swagger 解析失败: {e}")
        logger.warning(f"Swagger 解析失败: {e}")

        result = {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "failed",
            "summary": {
                "api_title": None,
                "api_version": None,
                "host": None,
                "base_path": None,
                "total_endpoints": 0,
                "endpoints": [],
                "swagger_url": target_url,
                "suggestion": "手动验证目标是否为有效 Swagger/OpenAPI 文档"
            },
            "errors": errors,
        }

        output_dir = os.path.join(RESULTS_BASE, TOOL_ID)
        os.makedirs(output_dir, exist_ok=True)
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(output_dir, f"{domain}_{ts_file}.json")
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        logger.info(f"结果已保存: {out_file}")
        return result

    # 6. 确定状态
    if len(endpoints) > 0:
        status = "success"
    else:
        status = "partial"
        errors.append("Swagger 文档解析成功但未发现任何 API 端点")

    summary = {
        "api_title": api_title,
        "api_version": api_version,
        "host": host,
        "base_path": base_path,
        "total_endpoints": len(endpoints),
        "endpoints": endpoints,
        "swagger_url": target_url,
    }

    result = {
        "tool": TOOL_ID,
        "target": domain,
        "time": timestamp,
        "status": status,
        "summary": summary,
        "errors": errors,
    }

    # 7. 保存结果到文件
    output_dir = os.path.join(RESULTS_BASE, TOOL_ID)
    os.makedirs(output_dir, exist_ok=True)
    ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(output_dir, f"{domain}_{ts_file}.json")

    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    logger.info(f"结果已保存: {out_file}")
    return result
