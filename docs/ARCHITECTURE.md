# bee-py — 架构蓝图 v1.0.1

> 面向：想理解「这玩意怎么工作」或「如何加新武器」的开发者。

---

## 一、核心理念

这不是一个脚本——是一套**分层插件化安全工具链**。四条铁律：

1. **扫描只发现，不利用** —— `saomiao.py` 只管测绘，输出标准 JSON
2. **核心能力下沉** —— 配置、日志、速率控制、代理池、HTTP会话等通用能力进入 `core/` 层
3. **利用只管打，不管扫** —— `tools/*.py` 只接收 JSON，不自己扫目标
4. **调度台当中间人** —— `diaodu.py` 读扫描结果 → 匹配工具 → 交互式调度

```
saomiao.py ──输出JSON──▶ data/scans/ ──读取──▶ diaodu.py ──调用──▶ tools/*.py ──输出──▶ data/results/{tool}/
                                                                 ↓
                                               core层（config/logging/ratelimit/proxy/session/exploit）
                                                                 ↓
                                                      report.py ──聚合──▶ data/reports/*.html
```

---

## 二、目录结构（v3.1最终版）

```
bee-py/
│
├── saomiao.py              # 🔍 资产测绘引擎（入口1）- 端口/目录/指纹/API提取
├── diaodu.py               # 🎮 调度台（入口2）- 自动匹配+交互式漏洞利用
├── report.py               # 📊 HTML报告生成器 - 可视化渗透报告
├── utils.py                # 🛠️  通用工具函数
├── config.yaml             # ⚙️  配置文件
├── requirements.txt        # Python依赖
│
├── core/                   # ⚙️  核心能力层（v3.0+v3.1整合）
│   ├── __init__.py
│   ├── config.py           # 🆕 v3.1新增：统一配置管理 - 单例模式全局配置
│   ├── logging.py          # 🆕 v3.1新增：统一日志系统 - 线程安全彩色输出
│   ├── ratelimit.py        # 自适应速率控制器 - 五类状态监控+动态调速
│   ├── proxy.py            # 代理池管理 - 多协议支持+健康检查
│   ├── session.py          # 安全HTTP会话 - SSL验证+重试+随机UA+CDN过滤
│   └── exploit.py          # 漏洞利用基类
│
├── tools/                  # 🗡️ 漏洞插件层（兵器库）- 共16个工具
│   ├── __init__.py         # 工具注册表 + match_tools() 自动匹配引擎
│   ├── unauth.py           # 未授权访问检测&利用（Redis/MongoDB/ES等）
│   ├── weakpass.py         # 弱口令爆破（多服务支持+后渗透信息收集）
│   ├── shiro_exploit.py    # Shiro反序列化检测&利用
│   ├── springboot_exploit.py # Spring Boot Actuator漏洞&heapdump下载
│   ├── thinkphp_exploit.py # ThinkPHP多版本RCE检测
│   ├── middleware_poc.py   # 中间件漏洞POC集合
│   ├── upload_exploit.py   # 文件上传漏洞检测&webshell上传
│   ├── weblogin.py         # Web后台登录爆破
│   ├── env_leak.py         # .env等环境配置泄露提取
│   ├── git_leak.py         # Git源码泄露复原
│   ├── swagger_leak.py     # 🆕 v3.1增强：Swagger/OpenAPI接口审计
│   ├── backup_leak.py      # 备份文件下载&解压
│   ├── cve_version.py      # CVE版本漏洞比对
│   ├── webshell.py         # Webshell交互终端
│   ├── injection.py        # 🆕 v3.1新增：SQL/XSS/LFI综合注入检测
│   └── bruteforce.py       # 🆕 v3.1新增：SSH智能防封爆破+深度后渗透
│
├── data/                   # 📁 运行数据目录（自动创建）
│   ├── scans/              # 侦察阶段输出（标准化JSON：scan_{domain}_{ts}.json）
│   ├── results/            # 利用阶段输出（按工具分子目录：result_{domain}_{ts}.json）
│   │   ├── unauth/
│   │   ├── weakpass/
│   │   ├── injection/
│   │   ├── bruteforce/
│   │   ├── swagger_leak/
│   │   └── ...（每个工具一个子目录）
│   ├── reports/            # HTML报告输出（report_{domain}_{ts}.html）
│   └── cache/              # 临时下载缓存
│
├── dicts/                  # 📖 字典资源目录
│   ├── web_paths.txt       # Web路径字典
│   ├── weakpass.txt        # 通用弱口令字典
│   ├── ssh_password.txt    # SSH专用密码字典
│   ├── username.txt        # 用户名字典
│   ├── lfi_payloads.txt    # LFI Payload字典
│   └── subdomains.txt      # 子域名字典
│
├── docs/                   # 📚 文档目录
│   ├── ARCHITECTURE.md     # 本文档 - 架构蓝图
│   ├── GETTING_STARTED.md  # 小白零基础入门教程
│   ├── COMMANDS.md         # 日常命令参考手册
│   └── FAQ.md              # 常见问题解答
│
└── tools_ext/              # � 扩展工具目录（预留）
```

### 分层设计原则

| 层级 | 职责 | 依赖规则 |
|---|---|---|
| 入口层（根目录py） | 用户交互、流程调度 | 可依赖core层和tools层 |
| core核心层 | 通用能力（配置/日志/速率/代理/会话） | 不依赖tools层 |
| tools插件层 | 漏洞检测/利用逻辑 | 可依赖core层，工具之间互不依赖 |
| data目录 | 运行时数据输出 | 不放入代码 |
| dicts目录 | 字典资源 | 纯文本文件 |
| docs目录 | 文档 | 不包含代码 |

---

## 三、核心模块详解

### 3.1 core/config.py - 统一配置管理（v3.1新增）

**功能特性**：
- 基于dataclass的类型安全配置
- 单例模式 `get_config()` 全局访问
- 支持从config.yaml加载配置
- 分为AppConfig（全局）和ScanConfig（扫描参数）

**配置参数**：
```python
@dataclass
class ScanConfig:
    threads: int = 50              # 默认线程数
    timeout: int = 8               # 请求超时(秒)
    verify_ssl: bool = True        # SSL证书验证
    rate_limit_preset: str = "normal"  # fast/normal/safe三档
    delay: float = 0.05            # 初始请求间隔(秒)
    min_delay: float = 0.01        # 最小间隔(秒)
    max_delay: float = 10.0        # 最大间隔(秒)
```

### 3.2 core/logging.py - 统一日志系统（v3.1新增）

**功能特性**：
- 线程安全彩色日志输出
- 支持8种日志级别：info/success/warning/error/raw/exploit/vuln/debug
- 全局单例 `get_logger()`
- 所有工具统一使用此日志，输出格式一致

### 3.3 core/ratelimit.py - 自适应速率控制器

**核心机制**：持续统计五类连接状态占比，动态调整并发线程数和单请求间隔：
- ✅ 连接成功
- ❌ 认证失败
- 🚫 连接被拒
- ⏱️ 超时
- 📭 无响应

**三档预设**：
- `fast` 极速模式：高并发，适合内网/授权测试
- `normal` 普通模式：平衡速度和安全（默认）
- `safe` 安全模式：低并发慢速，适合外网目标

### 3.4 core/proxy.py - 代理池管理

**功能特性**：
- 支持HTTP/HTTPS/SOCKS5多协议代理
- 支持带认证的代理（user:pass@host:port）
- 自动健康检查，故障代理自动摘除
- 三种选择策略：轮询(round_robin)、随机(random)、最少使用(least_used)

### 3.5 core/session.py - 安全HTTP会话

**安全特性**：
- 默认启用SSL证书验证（可通过-k禁用）
- 自动重试机制（指数退避）
- 随机User-Agent轮换
- CDN通配符响应过滤，减少误报
- 自动集成代理池和速率限制
- 超时控制，防止挂起

---

## 四、16个工具一览（v3.1）

| 工具ID | 名称 | 分类 | 自动运行 | 触发条件 |
|---|---|---|---|---|
| `unauth` | 未授权访问检测&利用 | 漏洞检测 | ✅ | 任意开放端口 |
| `weakpass` | 弱口令爆破&后渗透 | 凭据爆破 | ❌ | 手动运行 |
| `shiro_exploit` | Shiro反序列化 | 漏洞利用 | ✅ | HTTP/HTTPS端口 |
| `springboot_exploit` | Spring Boot Actuator漏洞 | 漏洞利用 | ✅ | HTTP/HTTPS端口+Spring指纹 |
| `thinkphp_exploit` | ThinkPHP RCE检测 | 漏洞利用 | ✅ | HTTP/HTTPS端口+ThinkPHP指纹 |
| `middleware_poc` | 中间件漏洞POC集合 | 漏洞检测 | ✅ | HTTP/HTTPS端口 |
| `upload_exploit` | 文件上传漏洞检测 | 漏洞利用 | ✅ | HTTP/HTTPS端口 |
| `weblogin` | Web后台登录爆破 | 凭据爆破 | ❌ | 手动运行 |
| `env_leak` | .env配置泄露利用 | 信息泄露 | ❌ | 手动运行 |
| `git_leak` | Git源码泄露复原 | 信息泄露 | ❌ | 手动运行 |
| `injection` | 🆕 SQL/XSS/LFI综合注入 | 注入检测 | ✅ | HTTP/HTTPS端口+PHP/API路径 |
| `bruteforce` | 🆕 SSH智能防封爆破 | 凭据爆破 | ❌ | 手动运行 |
| `swagger_leak` | Swagger/OpenAPI接口审计 | 信息泄露 | ❌ | /swagger-ui.html路径/API端点 |
| `backup_leak` | 备份文件下载利用 | 信息泄露 | ❌ | 手动运行 |
| `cve_version` | CVE版本漏洞比对 | 版本检测 | ❌ | 手动运行 |
| `webshell` | Webshell交互终端 | 漏洞利用 | ❌ | 手动运行 |

---

## 五、数据流

### 5.1 扫描结果（data/scans/scan_{domain}_{ts}.json）

这是整个工具链的**唯一标准格式**，所有工具都读这个结构：

```json
{
  "target_info": {
    "domain": "xxx.com",
    "ip": "1.2.3.4",
    "protocol": "https",
    "port": 443,
    "status_code": 200,
    "server": "nginx/1.20.1",
    "title": "网站标题",
    "behind_cdn": false,
    "cdn": null
  },
  "scan_time": "2026-06-28 14:00:00",
  "fingerprints": ["PHP/7.4.3", "ThinkPHP", "MySQL"],
  "ports": [
    {"port": 22, "service": "ssh", "banner": "OpenSSH 8.0", "confidence": "high"},
    {"port": 80, "service": "http", "banner": "nginx", "confidence": "high"}
  ],
  "directories": [
    {"path": "/admin", "status": 200, "size": 1234},
    {"path": "/swagger-ui.html", "status": 200, "size": 2345}
  ],
  "security_issues": [
    {"type": "ThinkPHP RCE", "severity": "Critical", "path": "/"}
  ],
  "api_endpoints": ["/api/user/list", "/api/user/add"],
  "ssl_info": {},
  "subdomains": [],
  "scan_config": {
    "threads": 50,
    "timeout": 8,
    "rate_limit_enabled": true
  }
}
```

### 5.2 工具结果（data/results/{tool}/result_{domain}_{ts}.json）

每个工具的输出统一格式，便于聚合生成报告：

```json
{
  "tool": "injection",
  "name": "Web注入检测 (SQL/XSS/LFI)",
  "target": "xxx.com",
  "time": "2026-06-28 14:30:00",
  "status": "success",
  "summary": "发现3个注入点",
  "findings": [
    {"type": "SQL注入", "severity": "Critical", "url": "...", "detail": "..."}
  ],
  "credentials": [
    {"service": "ssh", "username": "root", "password": "123456", "port": 22}
  ],
  "endpoint_count": 28,
  "public_endpoints": 5,
  "errors": []
}
```

**status字段说明**：
- `success` - 执行成功，有发现
- `partial` - 执行成功但无发现（正常）
- `failed` - 执行失败
- `skipped` - 跳过执行

---

## 六、工具注册与自动匹配

`tools/__init__.py` 的 `TOOL_REGISTRY` 是自动匹配中枢：

```python
TOOL_REGISTRY = {
    "injection": {
        "name": "Web注入漏洞快速检测",
        "desc": "SQL注入/XSS/LFI综合快速检测",
        "category": "injection",
        "priority": 0,
        "auto_run": True,
        "triggers": {
            "ports": ["http", "https"],
            "directories": ["php", "api", "id=", "page="]
        }
    }
}
```

**触发条件(triggers)**支持多种匹配方式：
- `ports`: 匹配端口服务名列表（如["ssh", "mysql"]）
- `directories`: 匹配敏感路径关键词（如["swagger", ".env"]）
- `fingerprints`: 匹配技术栈指纹（如["Spring Boot", "ThinkPHP"]）
- `security_issues`: 匹配已发现的漏洞类型
- `api_endpoints`: 匹配API端点特征（布尔值，True表示有API端点就触发）
- `any_open_port`: 只要有开放端口就匹配（布尔值）

---

## 七、工具接口规范

每个 `tools/*.py` 必须实现：

```python
# 1. 元信息（模块级变量）
TOOL_NAME = "工具名称"
TOOL_ID = "工具ID（必须与文件名一致）"
TOOL_DESC = "工具功能描述"
TOOL_CATEGORY = "credential"  # 分类见下文

# 2. 执行入口
def execute(scan_result: dict, target_info: dict) -> dict:
    """
    参数:
        scan_result: 完整扫描结果JSON（结构见上文）
        target_info: 提取好的目标信息 {domain, ip, protocol, base_url}
    
    返回标准化dict，结构见上文
    """
```

**工具分类(category)**：
- `credential` - 凭据爆破类 🔑
- `vuln` - 漏洞检测类 🚨
- `injection` - 注入检测类 💉
- `info_leak` - 信息泄露类 📋
- `exploit` - 漏洞利用类 💣
- `version` - 版本检测类 📦

---

## 八、如何添加新武器

以添加「XXE 漏洞检测」为例，4步搞定：

1. **创建 `tools/xxe.py`**，实现元信息 + `execute()` 接口（参考现有工具写法）
2. **在 `tools/__init__.py` 的 `TOOL_REGISTRY` 添加配置**：
```python
"xxe": {
    "name": "XXE 漏洞检测",
    "desc": "对XML接口进行XXE漏洞检测",
    "category": "injection",
    "priority": 3,
    "auto_run": False,  # 设置为True会自动运行
    "triggers": {
        "content_type": ["xml"],
        "api_endpoints": True
    }
}
```
3. **完成** —— diaodu.py 不需要改任何代码，自动识别新工具
4. 结果保存到 `data/results/xxe/` 目录，report.py 会自动识别并显示在报告中

---

## 九、精度与安全保障机制

| 机制 | 位置 | 作用 |
|---|---|---|
| 自适应三档速率控制 | core/ratelimit.py | 动态调速防IP封禁 |
| 代理池健康检查 | core/proxy.py | 故障自动摘除 |
| CDN/WAF 检测与过滤 | core/session.py | CDN通配符响应过滤，减少误报 |
| 端口可信度评级 | saomiao.py → scan_ports() | high/medium/low/cdn_noise四级 |
| 通配符404多级过滤 | saomiao.py | 长度+标题+内容采样多重校验 |
| 命令注入防护 | utils.py + 各工具 | subprocess.run列表参数，替换os.system |
| 动态导入白名单 | tools/__init__.py | 防止任意代码执行 |
| XSS防护 | report.py | html_escape转义所有输出 |
| 凭据脱敏 | 各工具 | 报告中密码只显示前4位+*** |

---

## 十、版本历史

| 版本 | 发布时间 | 主要更新 |
|---|---|---|
| v1.x | - | 基础扫描+11种工具 |
| v2.x | - | CDN识别+通配符404+字典自动更新 |
| v3.0 | 2025 | 架构分层+自适应调速+代理池+未授权/中间件POC |
| v3.1 | 2026-06-28 | ✅ 当前版本：<br>- 新增core/config.py统一配置<br>- 新增core/logging.py统一日志<br>- 新增tools/injection.py SQL/XSS/LFI综合注入检测<br>- 新增tools/bruteforce.py SSH智能防封爆破+深度后渗透<br>- 增强tools/swagger_leak.py（自动探测+内嵌JS提取+无认证端点测试）<br>- 合并新旧架构，删除冗余目录，统一文件命名规范<br>- 修复report.py兼容性问题，支持所有工具结果 |
| v3.2 | 计划中 | CDN识别增强+智能面板识别+更多CMS POC |
| v4.0 | 规划中 | 分布式扫描+批量目标支持 |

---

*最后更新：2026-06-28 v3.1 架构整合完成*
