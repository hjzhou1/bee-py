# 贡献指南

感谢你对 bee-py 的关注！

## 如何添加新武器

1. 在 `tools/` 下创建 `your_tool.py`
2. 实现 `TOOL_NAME`, `TOOL_ID`, `TOOL_DESC`, `TOOL_CATEGORY` 四个模块变量
3. 实现 `execute(scan_result, target_info)` 函数，返回标准 dict
4. 在 `tools/__init__.py` 的 `TOOL_REGISTRY` 中注册
5. `mkdir results/your_tool/`

**无需修改 diaodu.py**，调度台自动识别新工具。

## 接口规范

```python
TOOL_NAME = "工具中文名"
TOOL_ID = "tool_id"
TOOL_DESC = "一句话描述"
TOOL_CATEGORY = "credential"  # credential/injection/info_leak/exploit/version

def execute(scan_result: dict, target_info: dict) -> dict:
    """返回: {tool, target, time, status, summary, results, errors}"""
```

## 提交规范

- 一个 PR 只做一件事
- 新工具必须有 `execute()` 函数
- 无语法错误（`python -m py_compile tools/your_tool.py`）
