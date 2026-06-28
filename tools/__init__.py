"""
tools/ — bee-py 漏洞插件层
统一工具注册表 + 接口标准 + 智能匹配调度
"""

import os

# 工具结果统一输出目录
RESULTS_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "results")
os.makedirs(RESULTS_BASE, exist_ok=True)

# 端口到服务类型映射（新增更多服务）
PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "https",
    111: "rpcbind_nfs",
    139: "smb",
    445: "smb",
    11211: "memcached",
    2375: "docker",
    2376: "docker_tls",
    2181: "zookeeper",
    3306: "mysql",
    5432: "postgresql",
    5984: "couchdb",
    6379: "redis",
    7001: "weblogic",
    8080: "http-alt_jenkins",
    8088: "hadoop_yarn",
    8081: "http-alt",
    9000: "fastcgi_sonarqube",
    9090: "webserver",
    9200: "elasticsearch",
    9300: "elasticsearch_node",
    27017: "mongodb",
    27018: "mongodb_arbiter",
}

# ==================== 工具注册表 ====================
TOOL_REGISTRY = {
    "unauth": {
        "name": "未授权访问检测&利用",
        "desc": "检测Redis/MongoDB/Elasticsearch/Jenkins/Zookeeper/Docker/Memcached/Hadoop等未授权，自动RCE利用",
        "category": "exploit",
        "priority": 0,
        "auto_run": True,
        "triggers": {
            "any_open_port": True
        }
    },
    "weakpass": {
        "name": "弱口令爆破&后利用",
        "desc": "对 SSH/MySQL/Redis/FTP/PostgreSQL/MongoDB/Telnet 执行自适应字典爆破，爆破成功后自动执行命令/枚举数据库",
        "category": "exploit",
        "priority": 1,
        "triggers": {
            "ports": ["ssh", "mysql", "redis", "ftp", "postgresql", "mongodb", "telnet"]
        }
    },
    "shiro_exploit": {
        "name": "Shiro反序列化检测&利用",
        "desc": "检测Shiro框架rememberMe反序列化漏洞，爆破默认密钥，生成利用payload",
        "category": "exploit",
        "priority": 2,
        "auto_run": True,
        "triggers": {
            "ports": ["http", "https", "http-alt", "http-alt_jenkins", "weblogic", "webserver"],
            "fingerprints": ["shiro"]
        }
    },
    "springboot_exploit": {
        "name": "Spring Boot Actuator漏洞检测",
        "desc": "检测Actuator端点暴露、env配置覆盖RCE、jolokia JNDI注入、heapdump内存泄露",
        "category": "exploit",
        "priority": 2,
        "auto_run": True,
        "triggers": {
            "ports": ["http", "https", "http-alt", "webserver"],
            "fingerprints": ["spring", "springboot", "actuator"]
        }
    },
    "thinkphp_exploit": {
        "name": "ThinkPHP多版本RCE检测",
        "desc": "检测ThinkPHP 3.x/5.x/6.x远程代码执行漏洞，支持命令执行和写webshell",
        "category": "exploit",
        "priority": 2,
        "auto_run": True,
        "triggers": {
            "ports": ["http", "https", "http-alt", "webserver"],
            "fingerprints": ["thinkphp", "think"]
        }
    },
    "middleware_poc": {
        "name": "中间件漏洞POC检测",
        "desc": "检测Tomcat/WebLogic/Nexus/Harbor/Jolokia/Druid等主流中间件漏洞",
        "category": "vuln",
        "priority": 2,
        "auto_run": True,
        "triggers": {
            "ports": ["http", "https", "http-alt", "http-alt_jenkins", "weblogic", "webserver"]
        }
    },
    "upload_exploit": {
        "name": "文件上传漏洞检测&利用",
        "desc": "扫描常见上传端点，绕过限制自动上传webshell并验证",
        "category": "exploit",
        "priority": 3,
        "auto_run": True,
        "triggers": {
            "ports": ["http", "https", "http-alt", "webserver"]
        }
    },
    "weblogin": {
        "name": "Web 后台登录爆破",
        "desc": "自动识别管理员登录表单，尝试常见弱口令组合登录后台",
        "category": "credential",
        "priority": 3,
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
    "injection": {
        "name": "Web注入漏洞快速检测",
        "desc": "SQL注入/XSS跨站/LFI本地文件包含综合快速检测，独立实现无需依赖外部工具",
        "category": "vuln",
        "priority": 2,
        "auto_run": True,
        "triggers": {
            "any_open_port": True,
            "ports": ["http", "https", "http-alt", "http-alt_jenkins", "webserver"]
        }
    },
    "bruteforce": {
        "name": "SSH智能防封爆破&后渗透",
        "desc": "三级自适应降速防封禁SSH爆破，爆破成功后自动执行深度系统信息收集",
        "category": "exploit",
        "priority": 1,
        "triggers": {
            "ports": ["ssh"]
        }
    },
    "swagger_leak": {
        "name": "Swagger/OpenAPI 接口审计",
        "desc": "自动探测常见Swagger路径，支持JSON/YAML/内嵌JS解析，枚举API端点并测试无认证访问",
        "category": "info_leak",
        "priority": 2,
        "triggers": {
            "security_issues": ["Swagger"],
            "directories": ["swagger", "openapi", "api-docs", "doc.html"]
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
    "cve_version": {
        "name": "CVE 版本漏洞比对",
        "desc": "基于指纹识别结果查询已知CVE漏洞库",
        "category": "version",
        "priority": 4,
        "triggers": {
            "fingerprints": ["nginx", "apache", "iis", "wordpress", "drupal", "php", "mysql", "redis", "tomcat", "shiro", "spring", "weblogic", "thinkphp"]
        }
    },
    "sqli": {
        "name": "SQL注入深度检测(sqlmap)",
        "desc": "调用sqlmap对API端点和登录页进行深度SQL注入检测",
        "category": "injection",
        "priority": 5,
        "triggers": {
            "ports": ["http", "https", "http-alt"],
            "directories": ["php", "asp", "aspx", "jsp", "id=", "login", "admin"]
        }
    },
    "xss": {
        "name": "XSS跨站脚本检测",
        "desc": "对发现的Web登录页/搜索页进行反射型/DOM型XSS检测",
        "category": "injection",
        "priority": 5,
        "triggers": {
            "ports": ["http", "https", "http-alt"],
            "directories": ["search", "q=", "query", "input", "login"]
        }
    },
    "lfi": {
        "name": "本地文件包含检测",
        "desc": "检测路径穿越、本地/远程文件包含漏洞",
        "category": "exploit",
        "priority": 3,
        "auto_run": True,
        "triggers": {
            "ports": ["http", "https", "http-alt"],
            "directories": ["file=", "page=", "include=", "path=", "document="]
        }
    },
    "webshell": {
        "name": "Webshell交互终端",
        "desc": "连接已获取的webshell，提供交互式命令执行和一键信息收集",
        "category": "exploit",
        "priority": 10,
        "triggers": {}
    }
}


def match_tools(scan_result):
    """
    根据扫描结果智能匹配可用工具。
    返回: [(tool_id, tool_info, match_reason), ...]
    按 priority 排序（数字越小优先级越高）
    """
    matched = []
    directories = [d.get("path","") for d in scan_result.get("directories", [])]
    ports = [p.get("service","") for p in scan_result.get("open_ports", scan_result.get("ports", []))
             if p.get("confidence") != "cdn_noise"]
    security_issues = [i.get("type","") for i in scan_result.get("security_issues", [])]
    api_endpoints = scan_result.get("api_endpoints", [])
    fingerprints = [f.get("value","") for f in scan_result.get("fingerprints", [])
                    if f.get("type") in ("Tech", "Service")]
    has_open_ports = len(ports) > 0

    for tool_id, tool_info in TOOL_REGISTRY.items():
        reasons = []
        triggers = tool_info.get("triggers", {})

        # 任意开放端口触发
        if triggers.get("any_open_port") and has_open_ports:
            reasons.append("存在开放端口")

        # 端口匹配
        for svc in triggers.get("ports", []):
            for port_svc in ports:
                if svc in port_svc:
                    reasons.append(f"端口服务: {svc}")
                    break
            if reasons:
                break

        # 安全问题匹配
        for keyword in triggers.get("security_issues", []):
            for issue in security_issues:
                if keyword.lower() in issue.lower():
                    reasons.append(f"漏洞特征: {issue}")
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


def get_port_service(port):
    """根据端口号获取服务名称"""
    return PORT_SERVICE_MAP.get(int(port), "")
