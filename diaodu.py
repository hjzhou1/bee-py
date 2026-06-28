#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diaodu.py — bee-py · 漏洞利用调度台 v3.0
使用方式: python diaodu.py [-p proxies.txt] [--no-rate-limit]
功能: 浏览扫描结果 → 展示漏洞 → 推荐工具 → 交互式调度 → 收集战果
支持代理池和自适应速率限制配置，传递给所有攻击工具
v3.0新增：漏洞自动利用（Redis/Docker RCE、弱口令后利用、Shiro/SpringBoot/ThinkPHP RCE、文件上传拿shell）

⚠️ 【重要法律免责声明】
本工具仅用于授权的安全测试与教育目的。
使用本工具进行未经授权的渗透测试/攻击是严重违法行为。
使用者需自行承担因不当使用本工具产生的一切法律责任。
使用本工具即表示您已获得目标系统所有者的书面授权。
"""

import sys
import os
import json
import datetime
import importlib
import argparse
import inspect

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools import TOOL_REGISTRY, match_tools
from utils import validate_tool_id, sanitize_domain, Colors, check_dict_updates

# ==================== 配置 ====================
# 适配新目录结构，兼容旧目录
_base_dir = os.path.dirname(__file__)
SCANS_DIR = os.path.join(_base_dir, "data", "scans")
_old_scans_dir = os.path.join(_base_dir, "scans")
if not os.path.exists(SCANS_DIR) and os.path.exists(_old_scans_dir):
    SCANS_DIR = _old_scans_dir
os.makedirs(SCANS_DIR, exist_ok=True)

RESULTS_DIR = os.path.join(_base_dir, "data", "results")
_old_results_dir = os.path.join(_base_dir, "results")
if not os.path.exists(RESULTS_DIR) and os.path.exists(_old_results_dir):
    RESULTS_DIR = _old_results_dir
os.makedirs(RESULTS_DIR, exist_ok=True)

PROXY_FILE = "./proxies.txt"

# 使用统一颜色类
C = Colors

def print_banner():
    print(f"""{C.R}{C.BD}
   ██████  ██  █████  ██████  ██████  ██    ██ 
   ██   ██ ██ ██   ██ ██   ██ ██   ██ ██    ██ 
   ██   ██ ██ ███████ ██   ██ ██   ██ ██    ██ 
   ██   ██ ██ ██   ██ ██   ██ ██   ██ ██    ██ 
   ██████  ██ ██   ██ ██████  ██████   ██████  
          bee-py · 调度台 v3.0 — bee-py · scan → dispatch → exploit
{C.RS}""")

def list_scans():
    """列出 scans/ 下所有扫描结果"""
    if not os.path.exists(SCANS_DIR):
        os.makedirs(SCANS_DIR, exist_ok=True)
        return []

    files = sorted(
        [f for f in os.listdir(SCANS_DIR) if f.endswith('.json')],
        reverse=True
    )
    return [os.path.join(SCANS_DIR, f) for f in files]

def load_scan(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def extract_target_info(scan):
    """从扫描结果提取统一目标信息"""
    ti = scan.get("target_info", {})
    return {
        "domain": ti.get("domain", "unknown"),
        "ip": ti.get("ip", ""),
        "protocol": ti.get("protocol", "https"),
        "base_url": f"{ti.get('protocol','https')}://{ti.get('domain','')}",
        "cdn": ti.get("cdn"),
    }

def run_tool(tool_id, scan_result, target_info, config=None):
    """动态导入并执行工具，返回标准化结果"""
    # 工具ID白名单验证，防止任意代码执行
    if not validate_tool_id(tool_id):
        return {
            "tool": tool_id,
            "status": "failed",
            "summary": f"非法工具ID: {tool_id}",
            "results": [],
            "errors": ["invalid_tool_id"]
        }
    
    try:
        mod = importlib.import_module(f"tools.{tool_id}")
        if not hasattr(mod, "execute"):
            return {
                "tool": tool_id,
                "status": "failed",
                "summary": f"工具 {tool_id}.py 缺少 execute() 接口",
                "results": [],
                "errors": ["missing_execute_function"]
            }

        print(f"\n{C.B}{'='*60}{C.RS}")
        print(f"  🔧 执行: {getattr(mod, 'TOOL_NAME', tool_id)}")
        if config and config.get("proxy_file"):
            print(f"  🌐 代理池已启用")
        if config and config.get("rate_limit"):
            print(f"  ⏱️  智能速率限制已启用")
        print(f"{C.B}{'='*60}{C.RS}")

        # 执行工具：用inspect检查参数签名，避免except TypeError吞掉工具内部真实bug
        sig = inspect.signature(mod.execute)
        if 'config' in sig.parameters and config is not None:
            result = mod.execute(scan_result, target_info, config=config)
        else:
            result = mod.execute(scan_result, target_info)

        # 标准化
        if isinstance(result, dict):
            result.setdefault("tool", tool_id)
            result.setdefault("target", target_info["domain"])
            result.setdefault("time", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            result.setdefault("status", "success")

        # 保存到 results/{tool_id}/，清洗文件名防止路径遍历
        out_dir = os.path.join(RESULTS_DIR, tool_id)
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = sanitize_domain(target_info["domain"])
        out_file = os.path.join(out_dir, f"result_{domain}_{ts}.json")
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        return result

    except ImportError as e:
        return {
            "tool": tool_id,
            "status": "failed",
            "summary": f"工具导入失败: {e}",
            "results": [],
            "errors": [str(e)]
        }
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] 用户跳过当前工具{C.RS}")
        return {
            "tool": tool_id,
            "status": "skipped",
            "summary": "用户跳过",
            "results": [],
            "errors": ["user_skipped"]
        }
    except Exception as e:
        return {
            "tool": tool_id,
            "status": "failed",
            "summary": f"执行异常: {e}",
            "results": [],
            "errors": [str(e)]
        }

def main():
    parser = argparse.ArgumentParser(description="bee-py 调度台 v3.0")
    parser.add_argument("-p", "--proxy-file", help="代理IP列表文件路径")
    
    # 速率模式选择
    speed_group = parser.add_mutually_exclusive_group()
    speed_group.add_argument("--fast", action="store_true", help="极速模式：高并发高速扫描")
    speed_group.add_argument("--safe", action="store_true", help="安全模式：低并发慢速扫描")
    speed_group.add_argument("--no-rate-limit", action="store_true", help="禁用智能速率限制")
    
    parser.add_argument("--delay", type=float, default=0.05, help="初始请求间隔(秒) 默认: 0.05")
    parser.add_argument("--min-delay", type=float, default=0.01, help="最小间隔(秒) 默认: 0.01")
    parser.add_argument("--max-delay", type=float, default=10.0, help="最大间隔(秒) 默认: 10")
    parser.add_argument("--threads", "-t", type=int, default=50, help="线程数 默认: 50")
    parser.add_argument("--no-dict-update", action="store_true", help="不检查字典更新")
    parser.add_argument("--auto", "--full", action="store_true", dest="auto_run_all", help="全自动模式：自动选择最新扫描结果，运行所有匹配的auto_run工具")
    args = parser.parse_args()

    print_banner()
    
    # 根据速度模式调整参数
    rate_preset = "normal"
    if args.fast:
        rate_preset = "fast"
        args.delay = min(args.delay, 0.02)
        args.min_delay = min(args.min_delay, 0.005)
        args.threads = max(args.threads, 100)
        print(f"{C.G}[+] 极速模式已启用：100+线程猛爆破{C.RS}")
    elif args.safe:
        rate_preset = "safe"
        args.delay = max(args.delay, 0.2)
        args.min_delay = max(args.min_delay, 0.05)
        args.threads = min(args.threads, 20)
        print(f"{C.C}[i] 安全模式已启用：低并发慢速扫描{C.RS}")

    # 检查字典更新
    if not args.no_dict_update:
        print(f"{C.B}[*] 检查字典更新...{C.RS}")
        update_result = check_dict_updates(auto_update=True)
        if update_result.get("updated", 0) > 0:
            print(f"{C.G}[+] 字典更新完成: 更新{update_result['updated']}个{C.RS}")

    # 构建配置对象传递给工具
    proxy_file = args.proxy_file
    if not proxy_file and os.path.exists(PROXY_FILE):
        proxy_file = PROXY_FILE
    
    config = {
        "proxy_file": proxy_file,
        "rate_limit": not args.no_rate_limit,
        "rate_preset": rate_preset,
        "delay": args.delay,
        "min_delay": args.min_delay,
        "max_delay": args.max_delay,
        "threads": args.threads,
        "auto_update_dict": False,  # diaodu已检查字典更新，weakpass不重复检查
    }

    if proxy_file:
        print(f"{C.C}[i] 代理池配置: {proxy_file}{C.RS}")
    if not args.no_rate_limit:
        mode_text = {"fast": "极速", "normal": "标准", "safe": "安全"}[rate_preset]
        print(f"{C.C}[i] 智能速率限制: 已启用 ({mode_text}模式)，线程数 {args.threads}，间隔 {args.min_delay}-{args.max_delay}s{C.RS}")

    # 1. 列出扫描结果
    scan_files = list_scans()
    if not scan_files:
        print(f"{C.Y}[!] scans/ 目录下无扫描结果{C.RS}")
        print(f"    请先运行:  python saomiao.py <目标URL>")
        return

    print(f"\n{C.B}📁 侦察情报档案 ({len(scan_files)} 份):{C.RS}\n")
    for i, f in enumerate(scan_files, 1):
        fname = os.path.basename(f)
        # 解析文件名: scan_{domain}_{ts}.json
        parts = fname.replace("scan_", "").replace(".json", "").rsplit("_", 2)
        domain = parts[0] if parts else "unknown"
        ts = f"{parts[1]}_{parts[2]}" if len(parts) >= 3 else "unknown"
        size_kb = os.path.getsize(f) / 1024
        print(f"  [{i}] {domain}  ({ts}, {size_kb:.1f}KB)")

    # 2. 选择目标
    if args.auto_run_all:
        idx = 0
        print(f"\n{C.C}[*] 全自动模式：自动选择最新扫描结果{C.RS}")
    else:
        try:
            choice = input(f"\n{C.C}选择目标编号 (1-{len(scan_files)}) [默认=1]: {C.RS}").strip()
            idx = int(choice) - 1 if choice else 0
            if idx < 0 or idx >= len(scan_files):
                idx = 0
        except (ValueError, KeyboardInterrupt):
            print(f"\n{C.R}[!] 退出{C.RS}")
            return

    scan_path = scan_files[idx]
    scan = load_scan(scan_path)
    target_info = extract_target_info(scan)

    # 3. 展示漏洞摘要
    ports = scan.get("ports", [])
    valid_ports = [p for p in ports if p.get("confidence") != "cdn_noise"]
    cdn_noise_ports = [p for p in ports if p.get("confidence") == "cdn_noise"]
    directories = scan.get("directories", [])
    issues = scan.get("security_issues", [])
    fingerprints = scan.get("fingerprints", [])
    api_endpoints = scan.get("api_endpoints", [])
    subdomains = scan.get("subdomains", [])
    cdn = target_info.get("cdn")

    print(f"\n{C.BD}{'─'*60}{C.RS}")
    print(f"  🎯 目标: {C.G}{target_info['domain']}{C.RS}  ({target_info['base_url']})")
    print(f"  📅 扫描时间: {scan.get('scan_time', 'unknown')}")
    if cdn:
        print(f"  🌐 CDN: {C.Y}{cdn}{C.RS}")
    else:
        print(f"  🌐 CDN: 未检测到（直连源站）")
    print(f"{C.BD}{'─'*60}{C.RS}")

    print(f"\n{C.BD}🔍 发现摘要:{C.RS}")
    print(f"  子域名: {C.Y}{len(subdomains)}{C.RS}")
    print(f"  开放端口: {len(valid_ports)} (可信) / {len(cdn_noise_ports)} (CDN噪音)")
    for p in valid_ports:
        conf = p.get("confidence","?")
        conf_icon = {"high":"🟢","medium":"🟡","low":"🔴"}.get(conf, "⚪")
        print(f"    {conf_icon} {p['port']}/TCP [{p['service']}] ({conf})")
    print(f"  敏感路径: {C.Y}{len(directories)}{C.RS}")
    for d in directories[:8]:
        print(f"    - {d['path']} [{d['status']}]")
    if len(directories) > 8:
        print(f"    ... 共 {len(directories)} 个")
    print(f"  安全漏洞: {C.R}{len(issues)}{C.RS}")
    for iss in issues[:6]:
        sev_icon = {"Critical":"💀","High":"🔴","Medium":"🟡","Low":"🔵"}.get(iss.get("severity",""), "⚪")
        print(f"    {sev_icon} [{iss.get('severity','?')}] {iss.get('type','?')}")
    print(f"  技术指纹: {C.C}{len(fingerprints)}{C.RS}")
    for fp in fingerprints[:5]:
        print(f"    - {fp.get('value','?')}")
    print(f"  API端点: {C.C}{len(api_endpoints)}{C.RS}")

    # 4. 匹配工具
    matched = match_tools(scan)

    if not matched:
        print(f"\n{C.Y}[!] 未匹配到可执行工具（目标无已知漏洞特征）{C.RS}")
        return

    print(f"\n{C.BD}{'─'*60}{C.RS}")
    print(f"{C.BD}⚔️  推荐工具清单 ({len(matched)} 个):{C.RS}\n")

    for i, (tid, info, reasons) in enumerate(matched, 1):
        cat_icon = {"credential":"🔑","injection":"💉","info_leak":"📋","exploit":"💣","version":"📦","vuln":"🚨"}.get(info["category"],"🔧")
        print(f"  [{i}] {cat_icon} {info['name']} ({tid})")
        print(f"      匹配原因: {', '.join(reasons)}")
        print(f"      描述: {info['desc']}")
        print()

    # 5. 选择工具
    if args.auto_run_all:
        print(f"\n{C.C}[*] 全自动模式：自动运行所有匹配的高危漏洞利用工具{C.RS}")
        # 只选择auto_run=True的工具（高危exploit类）
        selected_indices = [i for i, (tid, info, reasons) in enumerate(matched) if info.get("auto_run", False)]
        if not selected_indices:
            print(f"{C.Y}[!] 无自动运行工具匹配，执行所有推荐工具{C.RS}")
            selected_indices = list(range(len(matched)))
        print(f"{C.C}[*] 将自动执行 {len(selected_indices)} 个工具{C.RS}\n")
    else:
        print(f"{C.BD}操作选项:{C.RS}")
        print(f"  [A] 执行全部推荐工具")
        print(f"  [1-{len(matched)}] 选择单个工具执行")
        print(f"  [1,3,5] 选择多个工具执行（逗号分隔）")
        print(f"  [Q] 退出\n")

        try:
            user_input = input(f"{C.C}请输入选择: {C.RS}").strip().upper()
        except KeyboardInterrupt:
            print(f"\n{C.R}[!] 退出{C.RS}")
            return

        if user_input == "Q":
            print(f"{C.Y}退出{C.RS}")
            return

        # 解析选择
        selected_indices = []
        if user_input == "A":
            selected_indices = list(range(len(matched)))
        else:
            try:
                parts = user_input.replace("，", ",").split(",")
                for p in parts:
                    p = p.strip()
                    if p.isdigit():
                        idx = int(p) - 1
                        if 0 <= idx < len(matched):
                            selected_indices.append(idx)
            except:
                print(f"{C.R}[!] 输入格式错误{C.RS}")
                return

        if not selected_indices:
            print(f"{C.R}[!] 未选择任何工具{C.RS}")
            return

    # 6. 执行
    all_status = []
    for idx in selected_indices:
        tool_id = matched[idx][0]
        result = run_tool(tool_id, scan, target_info, config=config)
        all_status.append(result)

        # 简短状态
        status_icon = {"success":"✅","partial":"⚠️","failed":"❌","skipped":"⏭️"}.get(result.get("status"), "❓")
        print(f"\n  {status_icon} {result.get('tool')}: {result.get('summary', '完成')}")

    # 7. 汇总
    print(f"\n{C.BD}{'='*60}{C.RS}")
    print(f"{C.G}📊 调度完成{C.RS}\n")
    for r in all_status:
        icon = {"success":"✅","partial":"⚠️","failed":"❌","skipped":"⏭️"}.get(r.get("status"), "❓")
        print(f"  {icon} [{r.get('tool')}] {r.get('summary','-')}")
    print(f"\n{C.C}结果文件位置: results/<工具名>/result_*.json{C.RS}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.R}[!] 调度终止{C.RS}")
