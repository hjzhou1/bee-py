#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upload.py — 文件上传漏洞检测
"""

import os, json, re, datetime, requests, mimetypes
from tools import RESULTS_BASE

TOOL_NAME = "文件上传漏洞检测"
TOOL_ID = "upload"
TOOL_DESC = "检测上传接口是否存在文件类型绕过、路径穿越等漏洞"
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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36",
}

# 常见上传接口关键词
UPLOAD_KEYWORDS = ["upload", "file", "avatar", "image", "photo", "attach", "import"]

# 检测用的无害文件
TEST_FILES = {
    "test.txt": (b"upload test file - security audit", "text/plain"),
    "test.jpg": (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\x00" * 100, "image/jpeg"),
    "test.php": (b"<?php echo 'audit_test'; ?>", "application/x-php"),
    "test.phtml": (b"<?php echo 'audit_test'; ?>", "application/x-php"),
    "test.html": (b"<script>alert(1)</script>", "text/html"),
}


def execute(scan_result, target_info):
    domain = target_info.get("domain", "unknown")
    base_url = target_info.get("base_url", "")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    errors = []

    # 查找上传相关页面
    directories = scan_result.get("directories", [])
    upload_targets = []
    for d in directories:
        path = d.get("path", "").lower()
        if any(kw in path for kw in UPLOAD_KEYWORDS) and d.get("status") == 200:
            upload_targets.append(d["path"])

    if not upload_targets:
        # 尝试常见上传路径
        for common in ["/upload", "/upload.php", "/api/upload", "/file/upload",
                       "/admin/upload", "/wp-admin/async-upload.php"]:
            url = base_url + common
            try:
                resp = requests.get(url, headers=HEADERS, timeout=5, verify=False, allow_redirects=False)
                if resp.status_code in [200, 405, 500]:  # 405=Method Not Allowed (only POST), 500 may still be valid
                    upload_targets.append(url)
            except:
                pass

    if not upload_targets:
        return {
            "tool": "upload", "target": domain, "time": now,
            "status": "skipped",
            "summary": "未发现上传接口",
            "results": [], "errors": errors
        }

    logger.info(f"发现 {len(upload_targets)} 个可能的上传接口")
    findings = []

    for target_url in upload_targets[:5]:
        logger.info(f"检测: {target_url}")

        for filename, (content, mime_type) in TEST_FILES.items():
            try:
                files = {"file": (filename, content, mime_type)}
                resp = requests.post(target_url, files=files, headers=HEADERS,
                                    timeout=10, verify=False, allow_redirects=True)

                finding = {
                    "url": target_url,
                    "filename": filename,
                    "status_code": resp.status_code,
                    "response_len": len(resp.text),
                }

                # 检查响应特征
                resp_lower = resp.text.lower()
                if any(kw in resp_lower for kw in ["upload successful", "success", "上传成功", "ok"]):
                    if filename.endswith((".php", ".phtml")):
                        finding["risk"] = "high"
                        finding["detail"] = f"疑似可上传 {filename} 文件（服务器接受）"
                        logger.warning(f"高危: {target_url} 接受 {filename}")
                    else:
                        finding["risk"] = "info"
                        finding["detail"] = f"上传 {filename} 成功"
                elif resp.status_code in [200, 201, 302]:
                    finding["risk"] = "medium"
                    finding["detail"] = f"上传 {filename} 返回 {resp.status_code}，需手动验证"
                else:
                    finding["risk"] = "low"
                    finding["detail"] = f"上传 {filename} 返回 {resp.status_code}"

                # 提取上传文件路径
                path_patterns = [r'"url"\s*:\s*"([^"]+)"', r"'url'\s*:\s*'([^']+)'",
                                r'"(/uploads/[^"]+)"', r"'(/uploads/[^']+)'"]
                for pat in path_patterns:
                    m = re.search(pat, resp.text)
                    if m:
                        finding["uploaded_path"] = m.group(1)
                        break

                findings.append(finding)

            except requests.exceptions.ConnectionError:
                logger.warning(f"连接失败: {target_url}")
                break
            except Exception as e:
                errors.append(str(e))

    # 汇总
    high_risks = [f for f in findings if f.get("risk") == "high"]
    status = "success" if findings else "skipped"
    summary = f"检测 {len(upload_targets)} 个接口"
    if high_risks:
        summary += f"，{len(high_risks)} 个高风险"

    result = {
        "tool": "upload", "target": domain, "time": now,
        "status": status, "summary": summary,
        "targets_tested": upload_targets,
        "findings": findings,
        "suggestion": "高风险项需手动验证上传文件是否可被执行",
        "errors": errors
    }

    # 保存
    out_dir = os.path.join(RESULTS_BASE, "upload")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(out_dir, f"result_{domain}_{ts}.json")
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result
