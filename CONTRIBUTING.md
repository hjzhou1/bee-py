# 贡献指南

感谢你对 bee-py v3.0 的关注！

## 目录结构说明

```
bee-py/
├── core/              # 核心调度层（限速/代理/会话）
├── tools/             # 漏洞插件层（所有检测工具）
├── docs/              # 文档体系
│   ├── archive/       # 旧文档归档
│   ├── ARCHITECTURE.md
│   ├── GETTING_STARTED.md
│   └── FAQ.md
├── dicts/             # 字典资源
├── data/              # 运行时数据
│   ├── scans/         # 扫描结果
│   └── results/       # 工具执行结果
├── saomiao.py         # 扫描入口
├── diaodu.py          # 调度入口
├── jieshi.py          # 报告生成
└── utils.py           # 工具函数
```

## 如何添加新工具/插件

1. 在 `tools/` 下创建 `your_tool.py`
2. 实现模块级常量：`TOOL_NAME`, `TOOL_ID`, `TOOL_DESC`, `TOOL_CATEGORY`, `TOOL_PRIORITY`
3. 实现 `execute(scan_result, target_info, **kwargs)` 函数，返回标准 dict
4. 在 `tools/__init__.py` 的 `TOOL_REGISTRY` 中注册，配置自动触发条件
5. 核心代码自动创建结果目录，无需手动 mkdir

**无需修改 diaodu.py 或 saomiao.py**，调度台自动识别新工具。

## 接口规范

```python
TOOL_NAME = "工具中文名"
TOOL_ID = "tool_id"
TOOL_DESC = "一句话描述工具功能"
TOOL_CATEGORY = "vuln"  # vuln/credential/injection/info_leak/exploit/version
TOOL_PRIORITY = 1       # 0=最高（自动运行）, 1=高, 2=中, 3=低

def execute(scan_result: dict, target_info: dict, **kwargs) -> dict:
    """
    返回格式:
    {
        "tool": TOOL_ID,
        "target": target,
        "time": isoformat,
        "status": "success" | "partial" | "failed" | "skipped",
        "summary": "一句话摘要",
        "results": [...],  # 详细发现列表
        "errors": [...]    # 错误信息列表
    }
    """
```

## 自动触发条件配置

在 `tools/__init__.py` 的 `TOOL_REGISTRY` 中配置 `triggers`：

```python
"your_tool": {
    "name": TOOL_NAME,
    "desc": TOOL_DESC,
    "category": TOOL_CATEGORY,
    "priority": 0,
    "auto_run": True,  # 是否在全选时自动运行
    "triggers": {
        "ports": ["ssh", "mysql"],           # 匹配端口服务名
        "any_open_port": False,              # 任意开放端口即触发
        "paths": [".env", "swagger.json"],   # 匹配发现的路径
        "fingerprints": ["WordPress", "Nginx"]  # 匹配指纹
    }
}
```

## 核心模块使用规范

### 自适应速率控制

```python
from core.ratelimit import AdaptiveRateLimiter, RateLimitConfig

config = RateLimitConfig(
    min_delay=0.3,
    max_delay=10.0,
    initial_delay=kwargs.get('delay', 0.8)
)
limiter = AdaptiveRateLimiter(config)

# 请求前等待
limiter.wait()

# 记录结果状态
# status: success/auth_failed/connection_refused/timeout/no_response
limiter.record_result("success")
```

### 代理池使用

```python
from core.proxy import ProxyPool

proxies = kwargs.get('proxies', [])
if proxies:
    proxy_pool = ProxyPool(proxies)
    proxy = proxy_pool.get_proxy()
    # 使用 proxy 发请求...
```

## 提交规范

- 一个 PR 只做一件事，保持原子性
- 新工具必须实现标准 `execute()` 接口
- 必须使用 `core/ratelimit.py` 进行速率控制，避免无脑发包
- 禁止使用 `os.system()`，命令执行必须用 `subprocess.run()` 加列表参数
- 无语法错误：`python -m py_compile tools/your_tool.py core/*.py`
- 报告输出必须使用 `html_escape()` 转义，防止XSS
