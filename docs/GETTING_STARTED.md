# bee-py — 新兵入伍指南

> 面向：第一次用这个工具的人。跟着走完就能独立完成一次完整的侦察→利用。

---

## 第 0 步：你需要什么

- **Python 3.8+**（macOS 自带，终端输入 `python3 --version` 确认）
- **可以联网**（需要下载依赖、弱口令字典、Git 源码等）
- **对目标的合法授权**（⚠️ 未经授权扫描他人网站违法）

---

## 第 1 步：安装

打开终端，把下面内容逐行粘贴执行：

```bash
# 进入项目目录
cd ~/Desktop/python

# 安装所有依赖（一条命令搞定）
pip install -r requirements.txt
```

如果看到 `Successfully installed ...` 就说明安装成功。如果有报错，见 [FAQ 常见问题](FAQ.md)。

---

## 第 2 步：扫描目标

```bash
python saomiao.py https://你的目标.com
```

终端会跑约 30-60 秒，依次看到：

```
============ CDN/WAF检测 ============   ← 自动判断是否在 CDN 后面
============ 子域名探测 ============     ← 找子域名
============ 端口扫描 ============       ← 扫 70+ 端口（CDN噪音自动过滤）
============ 路径爆破与漏洞验证 =========← 扫敏感路径（.env / .git / swagger...）
============ 技术栈指纹识别 ============ ← 识别 Nginx / WordPress / PHP ...
============ 安全响应头检查 ============ ← 检查 CSP / HSTS / ...
============ JS动态API提取 ============ ← 抓 JS 里的 API 路径
```

最终输出：

```
=====================================
扫描完成，结果已保存至: ./scans/scan_你的目标.com_20260627_090000.json
运行 python diaodu.py 打开调度台选择利用工具
```

---

## 第 3 步：看结果 + 选武器

```bash
python diaodu.py
```

你会看到：

```
📁 侦察情报档案 (1 份):
  [1] 你的目标.com  (20260627_090000, 12.3KB)

选择目标编号 (1-1) [默认=1]:
```

输入 `1`（或直接回车），调度台会展示详细情报：

```
🎯 目标: 你的目标.com
🌐 CDN: Cloudflare

🔍 发现摘要:
  子域名: 3
  开放端口: 2 (可信) / 65 (CDN噪音)     ← 自动过滤了假的端口
  敏感路径: 5
  安全漏洞: 3
  技术指纹: Nginx, jQuery
  API端点: 12

⚔️  推荐工具清单 (6 个):                    ← 自动匹配可用的攻击工具

  [1] 🔑 弱口令爆破          ← 因为扫到 SSH/MySQL 端口
  [2] 🔑 Web 后台登录爆破     ← 因为扫到 /admin /login 等后台地址
  [3] 📋 .env 配置泄露利用   ← 因为扫到 .env 文件
  [4] 📋 Git 源码泄露复原    ← 因为扫到 .git/HEAD
  [5] 💉 XSS 跨站脚本检测    ← 因为扫到登录页
  [6] 💉 SQL 注入检测        ← 因为扫到 API 端点
  [7] 📦 CVE 版本漏洞比对    ← 因为识别到 Nginx

操作选项:
  [A] 执行全部推荐工具       ← 一键全跑
  [1-7] 选择单个工具执行     ← 只想测某一个
  [1,2,3] 选择多个工具执行   ← 挑几个跑
  [Q] 退出
```

### 三种跑法举例

```
请输入选择: A          # 全部攻击，一键拉满
请输入选择: 2          # 只跑 .env 泄露利用
请输入选择: 1,3,6      # 跑弱口令 + Git + CVE
```

执行时每个工具会显示进度：

```
  ✅ weakpass: 发现 2 组弱口令
  ✅ env_leak: 提取 5 组敏感凭据
  ⚠️ git_leak: 未发现 Git 目录
```

---

## 第 4 步：看战果

所有结果都在 `results/` 下，按工具分类：

```bash
results/
├── weakpass/result_你的目标.com_20260627_090100.json    # → 弱口令战果
├── env_leak/result_你的目标.com_20260627_090200.json     # → .env 提取的密码
├── sqli/result_你的目标.com_20260627_090300.json         # → SQL 注入结果
└── ...
```

用这个命令快速扫一眼：

```bash
# 看某个工具的摘要
cat results/weakpass/result_*.json | python3 -m json.tool | head -20

# 看所有工具的结果汇总
for d in results/*/; do
  echo "=== $(basename $d) ==="
  cat $d/result_*.json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('summary','?'))"
done
```

---

## 第 5 步：有多目标怎么办

每扫一个目标，就在 `scans/` 下多一个 JSON 文件。调度台自动列出所有目标让你选：

```bash
python saomiao.py https://目标A.com     # scans/ 多一份
python saomiao.py https://目标B.com     # scans/ 再一份

python diaodu.py                         # 两份目标任你选
```

---

## 常用命令速查卡

```bash
# 扫描
python saomiao.py https://target.com
python saomiao.py target.com              # 没有 http:// 也行

# 调度
python diaodu.py                          # 交互式选择

# 只跑一个工具（高级用法，跳过调度台）
python -c "
import json, sys
sys.path.insert(0,'.')
from tools.weakpass import execute
scan = json.load(open('scans/scan_xxx.com_xxx.json'))
info = {'domain':scan['target_info']['domain'],'ip':scan['target_info']['ip'],'base_url':'https://'+scan['target_info']['domain']}
print(execute(scan, info)['summary'])
"

# 清理旧战果
ls -t scans/scan_*.json | tail -n +6 | xargs rm -f
```

---

## 遇到问题？

👉 看 [FAQ.md](FAQ.md) —— 链路详解、错误排查、调优建议全在里面。

---

*搞定。从安装到战果不超过 5 步。*
