# bee-py v1.0.1 — 自动化渗透测试框架

## 这是什么

一键扫描网站漏洞的工具。输入网址，自动发现开放端口、敏感路径、Web框架、API文档泄露、未授权访问。

```bash
# 快速扫描
python -m bee_cli scan example.com --quick

# 完整扫描 + 自动漏洞利用
python -m bee_cli scan example.com --full

# 深度地毯式扫描（全量字典 ~7万条路径）
python -m bee_cli scan example.com --deep
```

## 30秒安装

```bash
# 1. 克隆项目
git clone <项目地址>
cd bee-py

# 2. 安装依赖
pip install -r requirements.txt

# 3. 扫描目标（必须是你自己授权的主机！）
python -m bee_cli scan 你的网站.com --quick
```

字典文件首次运行时会自动从 GitHub SecLists 下载，无需手动配置。

## 能扫到什么

### 扫描引擎
| 模块 | 做什么 | 怎么判定的 |
|------|--------|-----------|
| 端口扫描 | 检测 144 个常用端口 | TCP 连接测试，banner 抓取 |
| 路径爆破 | 探测敏感文件/后台 | GET 请求 + 通配符404过滤 |
| CDN检测 | 识别 14 种 CDN/WAF | 响应头特征匹配 + DNS多IP + 随机路径验证 |
| 指纹识别 | 鉴定 Web 框架 | HTML 特征码 + Server头 + X-Powered-By |
| SSL检查 | 评估加密配置 | TLS 版本/套件/证书 |

### 攻击武器（14个插件）
| 武器 | 干什么 | 怎么判定成功 |
|------|--------|-------------|
| 未授权访问 | 检测 Redis/Docker/Jenkins 等 8 种未授权 | 连接成功 + 读取数据/执行命令 |
| 弱口令爆破 | SSH/MySQL/Redis/FTP 等字典爆破 | 登录成功 + 执行系统命令 |
| Shiro反序列化 | 检测 Shiro rememberMe RCE | 100+ 密钥爆破 + 命令执行验证 |
| Spring Boot | 检测 Actuator 端点暴露 | 25+ 端点 GET 探测 + 内容验证 |
| ThinkPHP RCE | 3.x/5.x/6.x 多版本 RCE | HTTP 请求 + 命令执行回显 |
| 中间件POC | WebLogic/Tomcat/Nexus 漏洞 | POC 请求 + 响应特征匹配 |
| 文件上传 | 上传 webshell 并验证 | 30+ 端点扫描 + 后缀绕过 + shell 验证 |
| .env泄露 | 下载 .env 提取密码 | 文件下载 + 正则提取凭据 |
| Git泄露 | 复原 .git 源码 | HEAD/objects 探测 |
| Swagger泄露 | 枚举 API 端点 | swagger.json 解析 |
| 备份泄露 | 下载解压备份文件 | .zip/.sql 下载 |
| Web后台爆破 | 弱口令登录后台 | 表单识别 + 响应差异判断 |
| CVE比对 | 指纹 → CVE 漏洞库 | 版本号提取 + 数据库匹配 |
| Webshell终端 | 连接已有 webshell | 命令执行 + 10类信息收集 |

## 扫描结果在哪里

```
data/
├── scans/          ← 扫描结果 JSON
├── results/        ← 各插件详细结果（按工具分目录）
│   ├── springboot/
│   ├── weakpass/
│   └── ...
└── reports/        ← HTML/JSON 报告
```

### 查看报告
```bash
python -m bee_cli report      # 生成 HTML 报告
open data/reports/report_*.html  # 浏览器打开
```

## 弱口令爆破成功的输出示例

```
[EXPLOIT] SSH爆破成功! root:123456
```

结果文件 `data/results/weakpass/result_xxx.json`：
```json
{
  "credentials": [
    {"service": "ssh", "username": "root", "password": "123456", "port": 22}
  ],
  "status": "success",
  "summary": "发现 1 组弱口令"
}
```

## 项目结构

```
bee-py/
├── bee_core/       # 核心层：日志/配置/速率/代理/会话
├── bee_scanners/   # 扫描层：端口/路径/CDN/指纹/SSL/API
├── bee_plugins/    # 武器层：14个攻击插件
├── bee_reports/    # 报告层：HTML/JSON
├── bee_cli/        # 命令行入口
├── tools/          # 旧版工具（插件适配器动态加载）
├── dicts/          # 字典文件（自动下载）
├── data/           # 运行时输出
└── config.yaml     # 全局配置
```

## CDN 检测机制

1. **响应头匹配**：检查 Server/X-Cache/CF-Ray 等 14 种 CDN 签名头
2. **DNS 多 IP**：解析到 >8 个 IP → CDN
3. **随机路径验证**：发 3 个不存在路径，全部返回相同内容 → wildcard 确认
4. **自动过滤器**：所有 HTTP 插件发出的请求，wildcard 响应自动改为 404，杜绝假阳性
