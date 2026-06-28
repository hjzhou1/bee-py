# 📖 bee-py 命令参考手册

> 所有命令的完整参数说明，日常使用查这一篇就够了。
> Mac/Linux用 `python3`，Windows用 `python`，根据自己系统替换。

---

## 目录

1.  [主入口命令](#主入口命令)
    - [saomiao.py - 资产测绘引擎](#saomiaopy---资产测绘引擎)
    - [diaodu.py - 调度台](#diaodupy---调度台)
    - [report.py - HTML报告生成](#reportpy---html报告生成)
2.  [工具直接运行命令](#工具直接运行命令)
3.  [代理配置格式](#代理配置格式)
4.  [字典说明](#字典说明)

---

## 主入口命令

---

### saomiao.py - 资产测绘引擎

**功能**：端口扫描、服务识别、指纹识别、目录扫描、API端点提取、自动漏洞初筛。

#### 完整命令格式
```bash
python3 saomiao.py <目标> [参数]
```

#### 参数说明

| 短参数 | 长参数 | 说明 | 默认值 |
|---|---|---|---|
| `<目标>` | - | **必填**，目标域名或IP，支持http/https前缀 | - |
| `-h` | `--help` | 显示帮助信息 | - |
| `-t N` | `--threads N` | 并发线程数，越大越快越容易被封 | 50 |
| `-T N` | `--timeout N` | 单次请求超时时间（秒） | 8 |
| `-k` | `-insecure` | 不验证SSL证书（自签名证书/证书错误时用） | 关闭（验证） |
| `-p 文件` | `--proxy-file 文件` | 代理IP池文件路径，一行一个代理 | 不使用代理 |
| | `--fast` | 极速模式预设（高并发+短间隔，适合内网/授权测试） | - |
| | `--normal` | 普通模式预设（平衡速度和安全） | 默认 |
| | `--safe` | 安全模式预设（低并发+长间隔，适合外网目标） | - |
| | `--no-rate-limit` | 关闭自适应速率控制，固定线程全速跑 | 开启自适应 |
| | `--delay N` | 请求初始间隔（秒），自适应会基于这个调整 | 0.05 |
| | `--min-delay N` | 请求最小间隔（秒），不会比这个更快 | 0.01 |
| | `--max-delay N` | 请求最大间隔（秒），遇到拦截不会比这个更慢 | 10.0 |

#### 常用命令示例

1.  **普通扫描（默认参数）**
    ```bash
    python3 saomiao.py example.com
    ```

2.  **外网安全扫描，防封IP**
    ```bash
    python3 saomiao.py example.com --safe -k
    ```

3.  **内网极速扫描**
    ```bash
    python3 saomiao.py 192.168.1.100 --fast -t 100
    ```

4.  **使用代理IP池扫描**
    ```bash
    python3 saomiao.py example.com -p proxies.txt -k
    ```

5.  **自定义速度和超时**
    ```bash
    python3 saomiao.py example.com -t 30 -T 15 --delay 0.5
    ```

---

### diaodu.py - 调度台

**功能**：读取最新扫描结果，自动匹配适合的漏洞工具，支持交互式选择或全自动运行。

#### 完整命令格式
```bash
python3 diaodu.py [参数]
```

#### 参数说明

| 短参数 | 长参数 | 说明 | 默认值 |
|---|---|---|---|
| `-h` | `--help` | 显示帮助信息 | - |
| `-p 文件` | `--proxy-file 文件` | 代理IP池文件路径 | 不使用代理 |
| | `--fast` | 极速模式预设 | - |
| | `--safe` | 安全模式预设 | - |
| | `--delay N` | 请求初始间隔（秒） | 0.05 |
| | `--min-delay N` | 请求最小间隔（秒） | 0.01 |
| | `--max-delay N` | 请求最大间隔（秒） | 10.0 |
| | `--threads N` | 并发线程数 | 10 |
| | `-a` | `--auto` | 全自动运行所有匹配工具，不进入交互菜单 | 进入交互 |
| | `-f 文件` | `--file 文件` | 指定扫描结果JSON文件路径，不使用最新的 | 自动找最新 |

#### 常用命令示例

1.  **交互式菜单（默认）**
    ```bash
    python3 diaodu.py
    ```

2.  **全自动运行所有匹配工具**
    ```bash
    python3 diaodu.py --auto
    ```

3.  **全自动+安全模式+代理**
    ```bash
    python3 diaodu.py --auto --safe -p proxies.txt
    ```

4.  **指定某个历史扫描结果运行工具**
    ```bash
    python3 diaodu.py -f data/scans/scan_example.com_20260628_140000.json
    ```

#### 交互式菜单操作说明

进入调度台后：
- 输入**数字编号**：单独运行对应工具
- 输入 `a`：全自动运行所有匹配的工具，期间不需要你操作
- 输入 `q`：退出调度台
- 爆破类工具（weakpass/bruteforce/weblogin）默认不会自动勾选，全自动模式下会询问你是否运行

---

### report.py - HTML报告生成

**功能**：聚合所有扫描结果和工具结果，生成美观的HTML可视化报告。

#### 完整命令格式
```bash
python3 report.py [参数]
```

#### 参数说明

| 参数 | 说明 | 默认值 |
|---|---|---|
| `-h` | 显示帮助信息 | - |
| `-o 路径` | 指定报告输出路径和文件名 | 自动生成在data/reports/ |
| `-f 文件` | 指定扫描结果JSON文件路径 | 自动找最新的扫描结果 |

#### 常用命令示例

1.  **自动生成最新扫描的报告**
    ```bash
    python3 report.py
    ```

2.  **指定扫描结果生成报告**
    ```bash
    python3 report.py -f data/scans/scan_example.com_20260628_140000.json
    ```

3.  **指定报告输出位置**
    ```bash
    python3 report.py -o /Users/xxx/Desktop/report.html
    ```

---

## 工具直接运行命令

所有工具都可以不经过调度台，单独直接运行，适合单独测试某个漏洞的时候用。

> **注意**：单独运行工具不会自动读取扫描配置（代理/线程等），需要手动传参数。

| 工具ID | 命令格式 | 说明 |
|---|---|---|
| `unauth` | `python3 -m tools.unauth <IP> <端口>` | 检测指定IP端口的未授权访问（默认测Redis 6379等常见端口）<br>例子：`python3 -m tools.unauth 192.168.1.100 6379` |
| `shiro_exploit` | `python3 -m tools.shiro_exploit <URL>` | Shiro反序列化检测<br>例子：`python3 -m tools.shiro_exploit http://example.com/` |
| `springboot_exploit` | `python3 -m tools.springboot_exploit <URL>` | Spring Boot Actuator漏洞检测+heapdump下载<br>例子：`python3 -m tools.springboot_exploit http://example.com/` |
| `thinkphp_exploit` | `python3 -m tools.thinkphp_exploit <URL>` | ThinkPHP多版本RCE检测<br>例子：`python3 -m tools.thinkphp_exploit http://example.com/` |
| `webshell` | `python3 -m tools.webshell <URL> --pwd <密码参数>` | Webshell交互终端<br>例子：`python3 -m tools.webshell http://example.com/shell.php --pwd cmd` |

> 其他工具建议通过diaodu.py调度台运行，自动传入目标信息和配置，不容易出错。

---

## 代理配置格式

如果你要使用代理IP池，创建一个文本文件（比如叫proxies.txt），一行一个代理，支持以下格式：

```
# HTTP代理（无认证）
1.2.3.4:8080

# HTTP代理（带用户名密码）
user:password@5.6.7.8:8080

# HTTPS代理
https://9.10.11.12:443

# SOCKS5代理
socks5://13.14.15.16:1080

# SOCKS5代理（带认证）
socks5://user:pass@17.18.19.20:1080
```

> 注释行以 `#` 开头，会自动忽略。
> 代理池会自动做健康检查，不能用的代理会自动剔除。

---

## 字典说明

所有字典文件都在 `dicts/` 目录下，纯文本格式，你可以自己修改添加内容：

| 字典文件 | 用途 | 注意事项 |
|---|---|---|
| `web_paths.txt` | Web目录扫描字典 | 一行一个路径，不要带开头的/ |
| `weakpass.txt` | 通用弱口令密码字典 | 爆破的时候用，建议不要加太多，不然跑的慢 |
| `ssh_password.txt` | SSH专用密码字典 | SSH爆破优先用这个，命中率更高 |
| `username.txt` | 爆破用的用户名列表 | 常用用户名都在这里，比如root/admin/test等 |
| `lfi_payloads.txt` | LFI文件包含Payload字典 | injection工具测LFI的时候用 |
| `subdomains.txt` | 子域名字典 | 子域名扫描用（预留功能） |

> 修改字典不需要重启程序，下次扫描自动加载最新内容。

---

## 三档速率预设说明

| 预设 | 并发线程 | 初始间隔 | 适用场景 |
|---|---|---|---|
| `--fast` 极速 | 高 | 短 | 内网渗透测试、本地靶场、授权的高速测试 |
| `--normal` 普通 | 中等 | 中等 | 默认，大多数场景用这个，平衡速度和安全 |
| `--safe` 安全 | 低 | 长 | 外网目标、防护严格的站点、怕被封IP的时候用 |

> 如果你不确定用什么，就用默认的normal，或者外网直接用safe，稳一点。
