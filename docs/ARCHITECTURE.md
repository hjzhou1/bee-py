# bee-py — 架构蓝图

> 面向：想理解「这玩意怎么工作」或「如何加新武器」的人。

---

## 一、核心理念

这不是一个脚本——是一套**插件化安全工具链**。三条铁律：

1. **扫描只发现，不利用** —— `saomiao.py` 只管测绘，输出标准 JSON
2. **利用只管打，不管扫** —— `tools/*.py` 只接收 JSON，不自己扫目标
3. **调度台当中间人** —— `diaodu.py` 读扫描结果 → 匹配工具 → 交互式调度

```
saomiao.py ──输出JSON──▶ scans/ ──读取──▶ diaodu.py ──调用──▶ tools/*.py ──输出──▶ results/{tool}/
```

---

## 二、目录结构

```
python/
│
├── saomiao.py              # 侦察引擎（唯一入口1）
├── diaodu.py               # 调度台（唯一入口2）
├── requirements.txt
│
├── tools/                  # 兵器库
│   ├── __init__.py         # 注册表 + match_tools() 匹配引擎
│   ├── weakpass.py         # 弱口令爆破
│   ├── env_leak.py         # .env 提取
│   ├── git_leak.py         # Git 复原
│   ├── swagger_leak.py     # API 枚举
│   ├── backup_leak.py      # 备份解包
│   ├── xss.py              # XSS 检测
│   ├── sqli.py             # SQL 注入
│   ├── upload.py           # 上传漏洞
│   ├── cve_version.py      # CVE 比对
│   └── lfi.py              # 文件包含
│
├── scans/     # 扫描结果（标准化JSON）
├── results/   # 利用战果（按工具分子目录）
├── dict/      # 弱口令字典
├── cache/     # 临时下载
├── reports/   # 综合报告
│
└── docs/      # 文档
    ├── ARCHITECTURE.md     # 本文档
    ├── GETTING_STARTED.md  # 使用教程
    └── FAQ.md              # 常见问题
```

### 为什么这么放

| 原则 | 体现 |
|---|---|
| 入口在根 | `saomiao.py` / `diaodu.py` 直接 `python xxx.py` |
| 武器进库 | `tools/` 里全是插件，入口不调武器文件 |
| 结果不散落 | 每个工具有自己的 `results/{tool}/` 子目录 |
| 文档集中 | `docs/` 三份文档，各管各的 |

---

## 三、数据流

### 3.1 扫描结果（scans/scan_{domain}_{ts}.json）

这是整个工具链的**唯一标准格式**，所有工具都读这个结构：

```json
{
  "target_info": {
    "domain": "xxx.com",
    "ip": "1.2.3.4",
    "protocol": "https",
    "cdn": "Cloudflare"       // null = 直连
  },
  "scan_time": "2026-06-27 08:00:00",
  "subdomains": ["api.xxx.com"],
  "ports": [{
    "port": 3306,
    "service": "mysql",
    "banner": "...",
    "version": "MySQL 5.7.32",
    "confidence": "high"     // high / medium / low / cdn_noise
  }],
  "directories": [{
    "path": "https://xxx.com/.env",
    "status": 200,
    "content": "..."
  }],
  "fingerprints": [{
    "type": "Tech",
    "value": "Nginx (Web服务器)"
  }],
  "security_issues": [{
    "type": "环境配置泄露",
    "severity": "Critical",
    "path": "https://xxx.com/.env"
  }],
  "api_endpoints": [{"path": "/api/v1/users"}],
  "ssl_info": {...}
}
```

### 3.2 工具结果（results/{tool}/result_{domain}_{ts}.json）

每个工具的输出**也必须统一**，这样未来 `jieshi.py` 才能聚合：

```json
{
  "tool": "weakpass",
  "target": "xxx.com",
  "time": "2026-06-27 09:00:00",
  "status": "success",       // success / partial / failed / skipped
  "summary": "发现 2 组弱口令",
  "results": [...],
  "errors": []
}
```

### 3.3 target_info 传递

dispatch 调用每个工具时，传入两个参数：

| 参数 | 内容 | 示例 |
|---|---|---|
| `scan_result` | 完整扫描 JSON（dict） | 工具自己从里面捞需要的字段 |
| `target_info` | 提取好的目标摘要 | `{"domain":"xxx.com","ip":"1.2.3.4","base_url":"https://xxx.com","cdn":"Cloudflare"}` |

---

## 四、工具注册与匹配

`tools/__init__.py` 的 `TOOL_REGISTRY` 是匹配中枢：

```python
TOOL_REGISTRY = {
    "weakpass": {
        "name": "弱口令爆破",
        "priority": 1,                        # 排序优先级
        "triggers": {
            "ports": ["ssh", "mysql", ...],   # 端口有这些服务 → 匹配
        }
    },
    "cve_version": {
        "name": "CVE 版本漏洞比对",
        "triggers": {
            "fingerprints": ["nginx", "apache", ...],  # 指纹匹配 → 推荐
        }
    },
}
```

**匹配逻辑**（`match_tools()`函数）：
1. 遍历所有扫描结果字段（ports / directories / security_issues / fingerprints / api_endpoints）
2. 与每个工具的 `triggers` 比对
3. 按 `priority` 排序输出

---

## 五、工具接口规范

每个 `tools/*.py` 必须实现：

```python
# 1. 元信息（模块级变量）
TOOL_NAME = "弱口令爆破"
TOOL_ID = "weakpass"
TOOL_DESC = "对SSH/MySQL/Redis/FTP执行弱口令爆破"
TOOL_CATEGORY = "credential"   # credential / injection / info_leak / exploit / version

# 2. 执行入口
def execute(scan_result: dict, target_info: dict) -> dict:
    """
    必须返回标准化 dict:
    {
        "tool": TOOL_ID,
        "target": target_info["domain"],
        "time": "2026-01-01 00:00:00",
        "status": "success",
        "summary": "一句话摘要",
        "results": [...],
        "errors": []
    }
    必须自动保存到 RESULTS_BASE/{tool_id}/result_{domain}_{ts}.json
    """
```

---

## 六、如何添加新武器

以添加「XXE 漏洞检测」为例，4 步搞定：

1. **创建 `tools/xxe.py`**，实现 `TOOL_NAME` + `execute()`
2. **在 `tools/__init__.py` 的 `TOOL_REGISTRY` 加条目**：
```python
"xxe": {
    "name": "XXE 检测",
    "desc": "对XML接口进行XXE漏洞检测",
    "category": "injection",
    "priority": 5,
    "triggers": {
        "directories": ["xml", "soap", "wsdl"],
        "api_endpoints": ["*"]
    }
}
```
3. **`mkdir results/xxe/`**
4.**完成** —— diaodu.py 不需要改一行

---

## 七、精度保障机制

| 机制 | 位置 | 作用 |
|---|---|---|
| CDN/WAF 检测 | `saomiao.py → detect_cdn()` | 7 种 CDN 签名识别，端口扫描前标记 |
| 端口可信度 | `saomiao.py → scan_ports()` | high/medium/low/cdn_noise 四级 |
| 通配符 404 过滤 | `saomiao.py → detect_wildcard_404()` | difflib 相似度 85% 阈值 |
| 凭据脱敏 | 各工具 | 输出只显示前 4 字符 + *** |
| 下载上限 | `safe_download()` | 流式传输，100MB 截断防内存炸弹 |

---

## 八、路线图

| Phase | 内容 | 状态 |
|---|---|---|
| P1 | 精度修复（CDN/端口/通配符/命令行） | ✅ |
| P2 | 兵器库 + dispatcher | ✅ |
| P3 | 路径字典扩容(688条) + Web后台爆破 | ✅ |
| P4 | 网页爬虫 + 参数Fuzzing + 响应差异分析 | 🔲 |

---

*最后更新：2026-06-27*
