# bee-py 快速入门手册

---

## ⚠️ 法律红线

**只能扫描你自己有权限测试的目标！**
- ✅ 本地靶场、自己的网站、客户书面授权的目标
- ❌ 未授权的任何公网/内网系统
- 未经授权扫描是违法行为，后果自负

---

## � 30秒快速开始

已经装好Python和依赖？直接复制这三行命令就能用：

```bash
# 1. 进入bee-py目录（根据你实际放的位置改）
cd ~/Desktop/bee-py

# 2. 扫描目标（把后面的地址换成你要扫的目标）
python3 saomiao.py http://127.0.0.1:8080

# 3. 扫描完自动进调度台，输入a全自动跑所有漏洞工具，跑完生成报告
python3 report.py
```

> Windows用户把 `python3` 换成 `python`，`cd ~/Desktop/bee-py` 换成 `cd Desktop\bee-py`

---

## 📖 详细安装教程（第一次用看这里）

### 第一步：安装Python

#### Mac用户
1. 按 `Command+空格` 搜「终端」打开
2. 输入 `python3 --version`，显示3.7以上就OK
3. 没装就去 https://www.python.org/downloads/macos/ 下载安装包，一路下一步就行

#### Windows用户
1. 按 `Win+R` 输入 `cmd` 打开命令提示符
2. 去 https://www.python.org/downloads/windows/ 下载64位安装包
3. **一定要勾窗口最下面的「Add Python.exe to PATH」！** 不勾后面100%报错
4. 装完重开CMD，输入 `python --version` 显示版本号就成功了

#### Linux用户
一般自带Python3，没装就执行：
```bash
# Ubuntu/Debian/Kali
sudo apt update && sudo apt install python3 python3-pip -y
```

---

### 第二步：进入bee-py目录

把代码下载到桌面，然后进入目录：

**Mac/Linux:**
```bash
cd ~/Desktop/bee-py
```

**Windows:**
```cmd
cd Desktop\bee-py
```

执行 `ls`（Mac/Linux）或者 `dir`（Windows），能看到 `saomiao.py`、`diaodu.py`、`report.py` 三个文件就说明进对目录了。

---

### 第三步：安装依赖

在bee-py目录里执行：

**Mac/Linux:**
```bash
pip3 install -r requirements.txt
```

**Windows:**
```cmd
pip install -r requirements.txt
```

如果下载慢报错，换成国内源：
```bash
# Mac/Linux
pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# Windows
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

权限报错就在前面加sudo（Mac/Linux）或者右键CMD选「以管理员身份运行」（Windows）。

---

## 🎯 三个核心文件怎么用

永远记住工作流：**扫描 → 漏洞利用 → 生成报告**

| 文件 | 作用 |
|------|------|
| `saomiao.py` | 端口扫描、指纹识别、目录扫描、自动发现基础漏洞 |
| `diaodu.py` | 扫描完后，自动匹配适合的漏洞工具，可以手动选也可以全自动跑 |
| `report.py` | 把所有结果生成可视化HTML报告 |

---

## � 常用扫描参数

| 参数 | 作用 | 例子 |
|------|------|------|
| `-t 数量` | 线程数，越大越快越容易被封 | `-t 30` |
| `-T 秒数` | 请求超时，目标慢就调大 | `-T 15` |
| `-k` | 忽略SSL证书错误（自签名证书用） | `-k` |
| `-p 文件` | 用代理IP池防封 | `-p proxies.txt` |
| `--fast` | 极速模式，高并发（内网/授权测试用） | `--fast` |
| `--safe` | 安全模式，低并发慢速（外网目标用） | `--safe` |
| `--delay 秒` | 每次请求间隔，手动控速 | `--delay 1` |

例子：外网安全模式扫描
```bash
python3 saomiao.py example.com --safe -k
```

例子：内网极速扫描
```bash
python3 saomiao.py 192.168.1.100 --fast -t 100
```

---

## 📁 结果文件存在哪

所有文件都自动存在 `data/` 目录下：
```
data/
├── scans/       # 原始扫描结果
├── results/     # 各个漏洞工具的结果
│   ├── unauth/
│   ├── weakpass/
│   ├── injection/
│   └── ...
└── reports/     # 生成的HTML报告
```

---

## 💣 新手最容易踩的坑

### 1. 提示 command not found
- Mac/Linux用 `python3`/`pip3`，Windows用 `python`/`pip`
- Windows装Python一定要勾Add to PATH，没勾就重装一遍

### 2. 提示找不到文件/路径
说明你不在bee-py目录里，重新执行cd命令进入正确目录

### 3. 扫描一堆超时/连接失败
- 先ping目标看网络通不通
- 目标有WAF封你IP了，加 `--safe` 或者用代理
- 线程开太高了，降低线程数

### 4. HTTPS证书错误
加 `-k` 参数忽略证书验证：
```bash
python3 saomiao.py https://example.com -k
```

### 5. 为什么没自动跑弱口令爆破？
爆破类工具流量大容易被封，默认不自动跑，进调度台手动选或者输入a会问你要不要跑

### 6. Windows中文乱码
先执行 `chcp 65001` 再跑脚本，或者装Windows Terminal

### 7. 按Ctrl+C停不下来
多线程要等当前请求完成，多按几次或者直接关终端

---

## 📋 常用命令速查

- 全自动扫描+利用：扫描完进调度台输入 `a`
- 重新跑漏洞工具不重新扫描：`python3 diaodu.py`
- 单独跑某个工具：`python3 -m tools.unauth 192.168.1.100 6379`
- 生成报告：`python3 report.py`

更多命令看 `docs/COMMANDS.md`，遇到问题看 `docs/FAQ.md`

---

**最后再强调一遍：技术要用在正道上，先在本地靶场练熟了再碰真实目标。**
