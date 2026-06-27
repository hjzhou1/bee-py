#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diaodu.py — bee-py · 调度台
使用方式: python diaodu.py
功能: 浏览扫描结果 → 展示漏洞 → 推荐工具 → 交互式调度 → 收集战果
"""

import sys
import os
import json
import datetime
import importlib

# 将项目根目录加入路径，确保 tools 包可导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools import TOOL_REGISTRY, match_tools

# ==================== 配置 ====================
SCANS_DIR = os.path.join(os.path.dirname(__file__), "scans")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")

# ==================== 颜色 ====================
class C:
    G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'
    B = '\033[94m'; C = '\033[96m'; BD = '\033[1m'; RS = '\033[0m'

def print_banner():
    print(f"""{C.R}{C.BD}
   ██████  ██  █████  ██████  ██████  ██    ██ 
   ██   ██ ██ ██   ██ ██   ██ ██   ██ ██    ██ 
   ██   ██ ██ ███████ ██   ██ ██   ██ ██    ██ 
   ██   ██ ██ ██   ██ ██   ██ ██   ██ ██    ██ 
   ██████  ██ ██   ██ ██████  ██████   ██████  
          bee-py · 调度台 v1.0 — bee-py · scan → dispatch → exploit
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

def run_tool(tool_id, scan_result, target_info):
    """动态导入并执行工具，返回标准化结果"""
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
        print(f"{C.B}{'='*60}{C.RS}")

        result = mod.execute(scan_result, target_info)

        # 标准化
        if isinstance(result, dict):
            result.setdefault("tool", tool_id)
            result.setdefault("target", target_info["domain"])
            result.setdefault("time", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            result.setdefault("status", "success")

        # 保存到 results/{tool_id}/
        out_dir = os.path.join(RESULTS_DIR, tool_id)
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = target_info["domain"]
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
    print_banner()

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
        cat_icon = {"credential":"🔑","injection":"💉","info_leak":"📋","exploit":"💣","version":"📦"}.get(info["category"],"🔧")
        print(f"  [{i}] {cat_icon} {info['name']} ({tid})")
        print(f"      匹配原因: {', '.join(reasons)}")
        print(f"      描述: {info['desc']}")
        print()

    # 5. 交互式选择
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
        result = run_tool(tool_id, scan, target_info)
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
