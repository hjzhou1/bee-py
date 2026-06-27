# bee-py — 常见问题详解

> 面向：跑不通、看不懂、想调优的人。

---

## 一、链路全景

```
你输入目标 URL
    │
    ▼
saomiao.py  ─────────── 侦察六连 ──────────┐
│                                           │
│  ① CDN/WAF 检测 → 判断是不是 Cloudflare   │
│  ② 子域名探测 → crt.sh + 字典爆破         │
│  ③ 端口扫描 → 70+ 端口 + 可信度评级        │
│  ④ 路径爆破 → 80+ 敏感路径 + 漏洞验证      │
│  ⑤ 指纹识别 → Nginx/WordPress/PHP/…      │
│  ⑥ 安全头 + API 提取                     │
│                                           │
│  输出 → scans/scan_{域名}_{时间戳}.json    │
└───────────────────┬───────────────────────┘
                    │
                    ▼
diaodu.py  ───────── 交互式调度 ────────────┐
│                                           │
│  ① 列出 scans/ 下所有目标                  │
│  ② 展示漏洞摘要 + 工具推荐                 │
│  ③ 你选择: 全部 / 单个 / 几个             │
│  ④ 逐个调用 tools/*.py                    │
│                                           │
│  每个工具输出 → results/{tool}/result_*.json│
└───────────────────────────────────────────┘
```

---

## 二、扫描发现 → 工具对应表

> 扫出什么就匹配什么，人机自动对应。

| 扫描发现 | 字段来源 | 匹配工具 | 工具做什么 |
|---|---|---|---|
| admin / login / manage 等后台路径 | `directories` | `weblogin.py` | 自动识别登录表单→字典爆破→判断成功/失败 |
| 端口 22 SSH 开放 | `ports.service=ssh` | `weakpass.py` | SSH 弱口令爆破 |
| 端口 3306 MySQL 开放 | `ports.service=mysql` | `weakpass.py` | MySQL 弱口令爆破 |
| 端口 6379 Redis 开放 | `ports.service=redis` | `weakpass.py` | Redis 弱口令爆破 |
| 端口 21 FTP 开放 | `ports.service=ftp` | `weakpass.py` | FTP 弱口令爆破 |
| `.env` 文件可访问 | `directories` | `env_leak.py` | 下载 .env → 提取 DB密码/API密钥/云AK |
| `.git/HEAD` 可访问 | `directories` | `git_leak.py` | 读分支 → 读 remote → 判断 dump 可行性 |
| `swagger.json` 暴露 | `directories` | `swagger_leak.py` | 解析全部 API 端点 + 方法 + 参数 |
| `.zip/.tar.gz/.sql` 可下载 | `directories` | `backup_leak.py` | 下载 → 解包 → 搜索密码/配置 |
| login.php / search.php 页面 | `directories` | `xss.py` | 注入 5 种 XSS payload，检测反射 |
| API 端点 + login 页面 | `api_endpoints` + `directories` | `sqli.py` | sqlmap 自动检测 + 自研错误特征匹配 |
| upload / file 路径 | `directories` | `upload.py` | 模拟上传 PHP/phtml 检测类型绕过 |
| Nginx 1.2.4 / PHP 7.2 / WordPress 5.0 | `fingerprints` | `cve_version.py` | 内置 20 条 CVE → 版本比对 → 给出影响 |
| file= / page= / include= 参数 | `directories` | `lfi.py` | 路径穿越 + PHP wrapper LFI 检测 |
| 缺失 CSP / HSTS 安全头 | `security_issues` | 无工具 | 仅为报告项，提醒加固 |

### 新增：如果对方后台不叫 /admin 怎么办？

`saomiao.py` 现在从 `dict/web_paths.txt` 加载 **688 条**路径字典，覆盖：
- 中文命名：`houtai/` `guanli/` `guanliyuan/`
- 框架特化：`phpmyadmin/` `jenkins/` `confluence/` `nacos/` `grafana/`
- 非标命名：`backend/` `panel/` `cp/` `portal/` `cms/`
- 中间件：`solr/` `kibana/` `consul/` `etcd/` `actuator/`

想加自定义路径？编辑 `dict/web_paths.txt`，一行一个。首次运行 saomiao.py 时还会自动从 GitHub 下载 SecLists 开源字典（50000+条），自动去重合并。

### 工具是自研的还是调用开源项目？

**双管齐下：** 优先使用业界成熟工具，没装就自动拉取，拉不到就降级到自研逻辑。

| 工具 | 优先使用 | 自研降级 |
|---|---|---|
| `weakpass.py` | SecLists 字典（自动下载） | 内置 15×15 弱口令组合 |
| `saomiao.py` 路径爆破 | SecLists 50000+条字典 | dict/web_paths.txt 688条 |
| `xss.py` | XSStrike（自动 git clone） | 5种 payload 自研反射检测 |
| `sqli.py` | sqlmap（自动 git clone） | 30+ SQL错误特征匹配 |
| `git_leak.py` | git-dumper（自动 git clone） | 手动下载 .git 关键文件 |
| `lfi.py` | PayloadsAllTheThings 字典 | 内置 10 种 payload |

首次运行每个工具时，会自动检测外部工具是否存在，不存在则自动从 GitHub 下载到 `tools_ext/` 目录，全程无需手动操作。

---

## 三、为什么端口扫描几乎全开放？

🔴 **最常遇到的困惑**。

**原因：目标前面有 CDN（Cloudflare 最常见）。**

你发 TCP 连接 → Cloudflare 边缘节点替你握手 → 你的程序以为端口开放。

**怎么判断：**
- 调度台第一行会显示 `🌐 CDN: Cloudflare`（如果有）
- 端口列表里大量 `cdn_noise` 标签 = CDN 噪音
- dispatcher **不会**推荐对 `cdn_noise` 端口的爆破

**怎么办：**
- `cdn_noise` 级别的端口自动被 weakpass.py 跳过
- 想穿透 CDN 需要找到源站 IP（Censys/Shodan/历史 DNS 记录），这超出本工具范围

---

## 四、通配符 404 是什么？为什么过滤掉？

有些网站对不存在的路径不返回 404，而是返回 200 + 一个「页面没找到」的 HTML。如果不过滤，路径爆破会把所有路径都误判为「存在」。

**我们的方案：**
1. 先访问一个随机乱码路径（如 `/test_nonexist_a3f2e9c1`）
2. 记录返回的 HTML 内容
3. 之后每个路径的响应都和这个「已知 404」做**相似度比较**
4. 相似度 > 85% → 判定为通配符 404 → 过滤掉

比老方案（硬编码 50 字节差）准确得多，不怕动态时间戳。

---

## 五、安装报错怎么办

### `ModuleNotFoundError: No module named 'paramiko'`

```bash
pip install paramiko pymysql redis cryptography
```

### `pip: command not found`

用 `pip3` 代替 `pip`，或者先装 pip：
```bash
python3 -m ensurepip --upgrade
```

### 字典下载失败

GitHub 被墙或网络不好。手动解决：
1. 浏览器打开字典 URL（在 `tools/weakpass.py` 的 `DICT_URLS` 里找）
2. 下载 `username.txt` 和 `password.txt`
3. 放到 `dict/` 目录

---

## 六、执行报错怎么办

### 工具返回 `status: failed`

查看具体错误：
```bash
cat results/{工具名}/result_*.json | python3 -m json.tool | grep -A5 errors
```

常见原因：
| 错误 | 原因 | 解法 |
|---|---|---|
| `ConnectionRefusedError` | 目标端口未真正开放（CDN 误报） | 正常，该端口置信度为 `cdn_noise` |
| `timeout` | 目标响应太慢 | 调大 `TIMEOUT` 参数（在工具文件顶部） |
| `connection reset` | 被 WAF/IDS 阻断 | 降低线程数，增加间隔 |
| `SSLError` | 证书有问题 | 确认目标 URL 以 `https://` 开头 |

### 弱口令爆破极慢

用户名 × 密码 = 组合爆炸。假设 100 个用户名 × 10000 个密码 = **100 万次尝试**。

**优化方法：**
1. 减少字典行数（`dict/` 下删掉不常用的）
2. 减小 `THREAD_COUNT`（避免被 WAF 封 IP）
3. 只对高价值目标（SSH/MySQL）跑爆破，跳过 FTP

---

## 七、结果文件怎么看

每个 JSON 都是标准格式，看 `summary` 字段就知道结果：

```bash
# 快看摘要
cat results/weakpass/result_*.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['summary'])"

# 看详细战果
cat results/env_leak/result_*.json | python3 -m json.tool | less
```

**注意：** 凭据已脱敏，只显示前 4 个字符。完整凭据不写入文件，仅在终端实时输出。

---

## 八、工具选哪些跑？

### 保守策略（不会惊动目标）

选 `cve_version.py` + `swagger_leak.py` —— 纯信息收集，不主动发送攻击 payload。

### 标准策略（常规渗透）

全选 `[A]` —— 调度的默认推荐，覆盖所有匹配工具。

### 激进策略（只跑高价值攻击）

选 `weakpass.py` + `env_leak.py` + `sqli.py` —— 这三个能直接拿到凭证或数据。

---

## 九、为什么扫描到的漏洞有些没有对应工具？

| 漏洞类型 | 为什么没工具 |
|---|---|
| 缺失 CSP / HSTS 安全头 | 这是配置问题，不是可利用漏洞——告诉管理员去加就行 |
| 信息泄露类（Server 头暴露版本）| 已被 `cve_version.py` 覆盖——版本信息作为 CVE 匹配的输入 |
| 子域名 | 子域名本身不是漏洞——但如果子域名上有漏洞，另扫那个子域名 |

---

## 十、性能调优

| 参数 | 位置 | 默认值 | 建议 |
|---|---|---|---|
| `THREAD_COUNT`（扫描）| `saomiao.py` 顶部 | 30 | 外网 → 10-15，内网 → 30-50 |
| `TIMEOUT`（扫描）| `saomiao.py` 顶部 | 4s | 慢速目标 → 8s |
| `THREAD_COUNT`（爆破）| `tools/weakpass.py` 顶部 | 10 | WAF 敏感 → 3-5 |
| `TIMEOUT`（爆破）| `tools/weakpass.py` 顶部 | 3s | 慢速目标 → 6s |

---

*最后更新：2026-06-27*
