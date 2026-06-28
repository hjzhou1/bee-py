# -*- coding: utf-8 -*-
"""
swagger_leak.py - Swagger/OpenAPI 接口审计工具 v2.0
支持：传统JSON/YAML文档、内嵌JS(swagger-ui-init.js)提取、自动枚举API端点、无认证访问测试
"""

import os
import sys
import json
import re
import datetime
import requests
from typing import List, Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from tools import RESULTS_BASE
from utils import Colors

TOOL_NAME = "Swagger/OpenAPI 接口审计"
TOOL_ID = "swagger_leak"
TOOL_DESC = "Swagger/OpenAPI文档泄露检测，支持JSON/YAML/内嵌JS解析，枚举API端点并测试无认证访问"
TOOL_CATEGORY = "info_leak"

TIMEOUT = 10
VERIFY_SSL = False

SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml",
    "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/openapi.yaml",
    "/api-docs/swagger.json", "/api-docs/openapi.json",
    "/api-docs/swagger-ui-init.js",
    "/swagger-ui/swagger.json",
    "/doc.html",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "close",
}


class Logger:
    def info(self, msg): print(f"{Colors.BLUE}[INFO] {msg}{Colors.RESET}")
    def success(self, msg): print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    def warning(self, msg): print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
    def error(self, msg): print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
    def exploit(self, msg): print(f"{Colors.MAGENTA}[⚡] {msg}{Colors.RESET}")
    def raw(self, msg): print(msg)

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


def _discover_swagger_endpoint(base_url: str) -> Optional[tuple]:
    """主动探测常见Swagger路径，返回 (url, content, is_embedded_js) 或 None"""
    session = requests.Session()
    session.verify = VERIFY_SSL

    for path in SWAGGER_PATHS:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            resp = session.get(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
            if resp.status_code != 200:
                continue

            body = resp.text[:8000] if resp.text else ""
            content_type = resp.headers.get("Content-Type", "")

            if path.endswith(".js") and '"swaggerDoc"' in body:
                logger.success(f"发现内嵌API文档(JS): {path}")
                return (url, body, True)

            if "application/json" in content_type or body.strip().startswith("{"):
                try:
                    json.loads(body)
                    logger.success(f"发现API文档: {path}")
                    return (url, body, False)
                except json.JSONDecodeError:
                    pass

            if path in ["/doc.html"] and "swagger" in body.lower():
                logger.info(f"发现Swagger UI页面: {path}，尝试提取内嵌文档")
                js_path = "/api-docs/swagger-ui-init.js"
                js_url = f"{base_url.rstrip('/')}{js_path}"
                try:
                    js_resp = session.get(js_url, timeout=TIMEOUT, headers=HEADERS)
                    if js_resp.status_code == 200 and '"swaggerDoc"' in js_resp.text[:8000]:
                        logger.success(f"发现内嵌API文档(JS): {js_path}")
                        return (js_url, js_resp.text[:8000], True)
                except Exception:
                    pass

        except Exception:
            continue

    return None


def _parse_embedded_js(js_content: str) -> Optional[dict]:
    """从 swagger-ui-init.js 中提取内嵌的 swaggerDoc"""
    m = re.search(r'"swaggerDoc":\s*(\{.*?"paths":\s*\{)', js_content, re.DOTALL)
    if not m:
        return None

    title = re.search(r'"title":\s*"([^"]+)"', js_content)
    version = re.search(r'"version":\s*"([^"]+)"', js_content)
    paths_raw = re.findall(r'"(/\w+(?:/\w+)*)":\s*\{', js_content)

    if not paths_raw:
        return None

    paths = {}
    for p in sorted(set(paths_raw)):
        paths[p] = {"get": {"summary": ""}}

    return {
        "openapi": "3.0.0",
        "info": {
            "title": title.group(1) if title else "Unknown",
            "version": version.group(1) if version else "0.0.0",
        },
        "paths": paths,
    }


def _test_public_endpoints(endpoints: List[dict], base_url: str) -> List[dict]:
    """测试哪些端点无需认证即可访问（只测GET）"""
    public = []
    session = requests.Session()
    session.verify = VERIFY_SSL

    for ep in endpoints[:20]:
        if ep["method"] != "GET":
            continue
        url = f"{base_url.rstrip('/')}{ep['path']}"
        try:
            resp = session.get(url, timeout=5, headers=HEADERS, allow_redirects=False)
            if resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                if "json" in content_type or resp.text.strip().startswith("{"):
                    public.append({
                        "method": "GET",
                        "path": ep["path"],
                        "status": resp.status_code,
                        "sample": resp.text[:200],
                    })
        except Exception:
            pass
    return public


def _parse_spec(text: str, target_url: str) -> Optional[dict]:
    """解析Swagger/OpenAPI规范文档（JSON/YAML/内嵌JS）"""
    if target_url.endswith(".js") or '"swaggerDoc"' in text[:2000]:
        return _parse_embedded_js(text)

    if target_url.endswith((".yaml", ".yml")):
        try:
            import yaml
            return yaml.safe_load(text)
        except ImportError:
            pass

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    return None


def _extract_endpoints_from_spec(spec: dict) -> tuple:
    """从规范文档中提取端点列表和元信息"""
    endpoints = []
    info = spec.get("info", {})
    api_title = info.get("title", "")
    api_version = info.get("version", "")
    host = spec.get("host", "")
    base_path = spec.get("basePath", "")

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
                if isinstance(details, dict):
                    raw_params = details.get("parameters", [])
                    summary = str(details.get("summary", details.get("description", "")))[:120]
                    if isinstance(raw_params, list):
                        for p in raw_params:
                            if isinstance(p, dict):
                                params.append({
                                    "name": p.get("name", "?"),
                                    "in": p.get("in", "?"),
                                    "required": p.get("required", False),
                                    "type": p.get("type", p.get("schema", {}).get("type", "?")),
                                })
                else:
                    summary = ""

                endpoints.append({
                    "method": method_upper,
                    "path": f"{base_path}{path}",
                    "summary": summary,
                    "parameters": params,
                })

    return endpoints, api_title, api_version, host, base_path


def execute(scan_result, target_info):
    """
    执行 Swagger/OpenAPI 接口审计
    支持：自动探测常见路径、JSON/YAML/内嵌JS解析、端点枚举、无认证访问测试
    """
    domain = target_info.get("domain", "unknown")
    base_url = f"{target_info.get('protocol', 'https')}://{domain}"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    errors = []

    logger.info(f"目标: {base_url}")

    target_url = None
    text = None

    swagger_items = _extract_swagger_items(scan_result)

    json_urls = [
        s["path"] for s in swagger_items
        if any(x in s["path"].lower() for x in [".json", ".yaml", ".yml", ".js"])
    ]
    html_urls = [
        s["path"] for s in swagger_items
        if not any(x in s["path"].lower() for x in [".json", ".yaml", ".yml", ".js"])
    ]

    if json_urls:
        target_url = json_urls[0]
        logger.info(f"从扫描结果获取文档: {target_url}")
        content = safe_download(target_url)
        if content:
            text = content.decode("utf-8", errors="ignore")

    if not text and html_urls:
        target_url = html_urls[0]
        logger.info(f"发现Swagger UI页面: {target_url}，尝试提取内嵌文档")
        discovery = _discover_swagger_endpoint(base_url)
        if discovery:
            target_url, text, _ = discovery

    if not text:
        logger.info("扫描结果未直接命中，开始主动探测常见Swagger路径...")
        discovery = _discover_swagger_endpoint(base_url)
        if discovery:
            target_url, text, _ = discovery

    if not text or not target_url:
        result = {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "failed",
            "summary": {"api_title": None, "api_version": None, "host": None,
                        "base_path": None, "total_endpoints": 0, "endpoints": [],
                        "public_endpoints": 0,
                        "suggestion": "未发现Swagger/OpenAPI文档，可尝试手动访问/swagger-ui.html或/v2/api-docs"},
            "errors": ["未发现Swagger/OpenAPI相关文档"],
        }
        output_dir = os.path.join(RESULTS_BASE, TOOL_ID)
        os.makedirs(output_dir, exist_ok=True)
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(output_dir, f"result_{domain}_{ts_file}.json")
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        logger.info(f"结果已保存: {out_file}")
        return result

    spec = _parse_spec(text, target_url)
    if not spec:
        errors.append(f"文档解析失败: {target_url}")
        result = {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "failed",
            "summary": {"api_title": None, "api_version": None, "host": None,
                        "base_path": None, "total_endpoints": 0, "endpoints": [],
                        "public_endpoints": 0,
                        "swagger_url": target_url,
                        "suggestion": "文档格式无法识别"},
            "errors": errors,
        }
        output_dir = os.path.join(RESULTS_BASE, TOOL_ID)
        os.makedirs(output_dir, exist_ok=True)
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(output_dir, f"result_{domain}_{ts_file}.json")
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        logger.info(f"结果已保存: {out_file}")
        return result

    endpoints, api_title, api_version, host, base_path = _extract_endpoints_from_spec(spec)

    public_endpoints = []
    if endpoints:
        logger.success(f"API文档: {api_title} v{api_version}")
        logger.success(f"枚举到 {len(endpoints)} 个API端点")
        for ep in endpoints[:10]:
            logger.raw(f"    {ep['method']:6} {ep['path']}")

        public_endpoints = _test_public_endpoints(endpoints, base_url)
        if public_endpoints:
            logger.exploit(f"发现 {len(public_endpoints)} 个无需认证的公开端点:")
            for ep in public_endpoints[:10]:
                logger.warning(f"    {ep['method']:6} {ep['path']}")

    status = "success" if endpoints else "partial"
    if not endpoints:
        errors.append("文档解析成功但未发现API端点")

    summary = {
        "api_title": api_title,
        "api_version": api_version,
        "host": host,
        "base_path": base_path,
        "total_endpoints": len(endpoints),
        "endpoints": endpoints,
        "public_endpoints": len(public_endpoints),
        "public_endpoint_details": public_endpoints,
        "swagger_url": target_url,
    }

    result = {
        "tool": TOOL_ID,
        "target": domain,
        "time": timestamp,
        "status": status,
        "summary": summary,
        "errors": errors,
        "findings": [{"type": "无需认证API", "count": len(public_endpoints)}] if public_endpoints else [],
    }

    output_dir = os.path.join(RESULTS_BASE, TOOL_ID)
    os.makedirs(output_dir, exist_ok=True)
    ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(output_dir, f"result_{domain}_{ts_file}.json")
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    logger.info(f"结果已保存: {out_file}")
    return result
