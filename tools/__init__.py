"""
tools/ — bee-py
统一工具注册表 + 接口标准
"""

import os
import json

# 工具结果统一输出目录（项目根目录下的 results/）
RESULTS_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")

# ==================== 工具注册表 ====================
TOOL_REGISTRY = {
    "weakpass": {
        "name": "弱口令爆破",
        "desc": "对 SSH/MySQL/Redis/FTP 服务执行字典爆破",
        "category": "credential",
        "priority": 1,
        "triggers": {
            "ports": ["ssh", "mysql", "redis", "ftp"]
        }
    },
    "weblogin": {
        "name": "Web 后台登录爆破",
        "desc": "自动识别管理员登录表单，尝试常见弱口令组合登录后台",
        "category": "credential",
        "priority": 2,
        "triggers": {
            "directories": ["login", "admin", "signin", "manage", "panel",
                          "console", "dashboard", "backend", "houtai",
                          "guanli", "administrator", "wp-login"]
        }
    },
    "env_leak": {
        "name": ".env 配置泄露利用",
        "desc": "下载 .env 文件，提取数据库密码/API密钥等敏感凭据",
        "category": "info_leak",
        "priority": 2,
        "triggers": {
            "security_issues": ["环境配置泄露"],
            "directories": [".env"]
        }
    },
    "git_leak": {
        "name": "Git 源码泄露复原",
        "desc": "从 .git 目录提取分支信息、remote 地址，判断是否可完整 dump",
        "category": "info_leak",
        "priority": 2,
        "triggers": {
            "security_issues": ["Git源码泄露"],
            "directories": [".git"]
        }
    },
    "swagger_leak": {
        "name": "Swagger/OpenAPI 接口审计",
        "desc": "解析 swagger.json，枚举全部API端点+参数",
        "category": "info_leak",
        "priority": 2,
        "triggers": {
            "security_issues": ["Swagger"],
            "directories": ["swagger", "openapi"]
        }
    },
    "backup_leak": {
        "name": "备份文件利用",
        "desc": "下载 .zip/.tar.gz/.sql 等备份文件，解包提取敏感信息",
        "category": "info_leak",
        "priority": 3,
        "triggers": {
            "security_issues": ["备份"],
            "directories": [".zip", ".sql", ".tar.gz", ".bak"]
        }
    },
    "xss": {
        "name": "XSS 跨站脚本检测",
        "desc": "对发现的Web页面进行反射型/DOM型XSS检测（调用外部工具）",
        "category": "injection",
        "priority": 4,
        "triggers": {
            "directories": ["login", "search", "admin", "register", "contact"]
        }
    },
    "sqli": {
        "name": "SQL 注入检测",
        "desc": "对 API 端点和登录页进行 SQL 注入检测（调用 sqlmap）",
        "category": "injection",
        "priority": 4,
        "triggers": {
            "api_endpoints": ["*"],
            "directories": ["login", "admin"]
        }
    },
    "upload": {
        "name": "文件上传漏洞检测",
        "desc": "检测上传接口是否存在文件类型绕过等漏洞",
        "category": "exploit",
        "priority": 5,
        "triggers": {
            "directories": ["upload", "file", "admin"]
        }
    },
    "cve_version": {
        "name": "CVE 版本漏洞比对",
        "desc": "基于指纹识别结果查询已知CVE漏洞库",
        "category": "version",
        "priority": 6,
        "triggers": {
            "fingerprints": ["nginx", "apache", "iis", "wordpress", "drupal", "php", "mysql", "redis", "tomcat"]
        }
    },
    "lfi": {
        "name": "本地文件包含检测",
        "desc": "检测文件包含类漏洞（路径穿越等）",
        "category": "exploit",
        "priority": 5,
        "triggers": {
            "directories": ["index", "page", "file", "include", "download"]
        }
    }
}


def match_tools(scan_result):
    """
    根据扫描结果匹配可用工具。
    返回: [(tool_id, tool_info, match_reason), ...]
    按 priority 排序
    """
    matched = []
    directories = [d.get("path","") for d in scan_result.get("directories", [])]
    ports = [p.get("service","") for p in scan_result.get("ports", [])
             if p.get("confidence") != "cdn_noise"]
    security_issues = [i.get("type","") for i in scan_result.get("security_issues", [])]
    api_endpoints = scan_result.get("api_endpoints", [])
    fingerprints = [f.get("value","") for f in scan_result.get("fingerprints", [])
                    if f.get("type") in ("Tech", "Service")]

    for tool_id, tool_info in TOOL_REGISTRY.items():
        reasons = []
        triggers = tool_info.get("triggers", {})

        # 端口匹配
        for svc in triggers.get("ports", []):
            if svc in ports:
                reasons.append(f"端口发现: {svc}")
                break

        # 安全问题匹配
        for keyword in triggers.get("security_issues", []):
            for issue in security_issues:
                if keyword.lower() in issue.lower():
                    reasons.append(f"漏洞: {issue}")
                    break
            if reasons:
                break

        # 路径匹配
        for keyword in triggers.get("directories", []):
            if keyword == "*" and directories:
                reasons.append("存在Web路径")
                break
            for d in directories:
                if keyword.lower() in d.lower():
                    reasons.append(f"路径: {d}")
                    break
            if reasons:
                break

        # API 匹配
        if triggers.get("api_endpoints") and api_endpoints:
            reasons.append(f"API端点: {len(api_endpoints)} 个")

        # 指纹匹配
        for kw in triggers.get("fingerprints", []):
            for fp in fingerprints:
                if kw.lower() in fp.lower():
                    reasons.append(f"指纹: {fp}")
                    break
            if reasons:
                break

        if reasons:
            matched.append((tool_id, tool_info, reasons))

    # 按 priority 排序
    matched.sort(key=lambda x: x[1].get("priority", 99))
    return matched
