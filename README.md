# bee-py 🐝

> 扫描即情报，调度即打击 — 插件化渗透测试工具链

bee-py 是一套**侦察→调度→利用**三阶段自动化安全测试框架。扫描目标全栈资产，自动匹配攻击工具，交互式执行，生成可视化 HTML 报告。

---

## 快速开始

```bash
# 安装
pip install -r requirements.txt

# 侦察目标
python saomiao.py https://example.com

# 打开调度台，选择攻击工具
python diaodu.py

# 生成 HTML 报告
python jieshi.py
```

---

## 兵器库（11 种攻击工具）

| 工具 | 功能 |
|---|---|
| `weakpass` | SSH/MySQL/Redis/FTP 弱口令爆破 |
| `weblogin` | 管理员后台自动识别 + 登录爆破 |
| `env_leak` | .env 文件下载 → 提取数据库密码/API密钥 |
| `git_leak` | .git 目录读取 → 远程仓库地址 + dump 可行性 |
| `swagger_leak` | Swagger/OpenAPI 文档解析 → 全部 API 端点 |
| `backup_leak` | 备份文件下载 → ZIP/SQL解压 → 凭据提取 |
| `xss` | 反射型/DOM型 XSS 检测 (XSStrike集成) |
| `sqli` | SQL 注入检测 (sqlmap集成) |
| `upload` | 文件上传类型绕过检测 |
| `cve_version` | 组件版本 → 已知 CVE 漏洞比对 |
| `lfi` | 本地文件包含（路径穿越）检测 |

---

## 特色

- **双管齐下** — 优先调用 sqlmap/XSStrike 等成熟工具，没装自动 git clone，装不了降级自研
- **CDN 智能过滤** — 自动识别 Cloudflare/CloudFront 等 7 种 CDN，端口扫描不误报
- **端口可信度** — 四级评级 (high/medium/low/cdn_noise)，假阳性自动跳过
- **688 → 50000+** — 内置路径字典 + 自动下载 SecLists 大字典
- **通配符 404 过滤** — difflib 相似度算法，不怕动态时间戳

---

## 架构

```
saomiao.py → scans/ → diaodu.py → tools/*.py → results/
 (侦察)      (情报)    (调度台)     (兵器库)     (战果)
                                                ↓
                                          jieshi.py
                                          (HTML报告)
```

---

## 文档

- 📘 [架构蓝图](docs/ARCHITECTURE.md) — 数据流、工具接口、扩展指南
- 📗 [新兵入伍](docs/GETTING_STARTED.md) — 从安装到战果，5步走
- 📙 [常见问题](docs/FAQ.md) — 链路详解、错误排查、工具对应表

---

## 依赖

首次运行自动安装的外部工具：

| 工具 | 用途 | 安装方式 |
|---|---|---|
| sqlmap | SQL注入 | `git clone` |
| XSStrike | XSS检测 | `git clone` |
| git-dumper | Git复原 | `git clone` |
| SecLists 字典 | 路径爆破 | HTTP下载 |
| PayloadsAllTheThings | LFI载荷 | HTTP下载 |

---

## 免责声明

**仅供授权的安全测试使用。** 对未授权目标执行扫描、爆破、漏洞利用属于违法行为，使用者自行承担法律责任。

---

## License

MIT License — 详见 [LICENSE](LICENSE)
