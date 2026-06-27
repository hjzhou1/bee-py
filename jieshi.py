#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jieshi.py — HTML 渗透测试报告生成器
使用方式: python jieshi.py
功能: 汇总 scans/ + results/ 下所有数据，生成可视化 HTML 报告
"""

import os, sys, json, datetime, glob

SCANS_DIR = os.path.join(os.path.dirname(__file__), "scans")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

def _sev_color(sev):
    return {"Critical":"#dc2626","High":"#ea580c","Medium":"#f59e0b","Low":"#3b82f6"}.get(sev,"#6b7280")

def _status_icon(st):
    return {"success":"✅","partial":"⚠️","failed":"❌","skipped":"⊘"}.get(st,"❓")

def build_report(scan_file=None):
    """扫描 scans/ 和 results/，生成 HTML 报告"""

    # 查找最新扫描
    if not scan_file:
        scans = sorted(glob.glob(os.path.join(SCANS_DIR, "scan_*.json")), reverse=True)
        if not scans:
            print("❌ scans/ 目录下无扫描结果，请先运行 saomiao.py")
            return None
        scan_file = scans[0]

    with open(scan_file, 'r', encoding='utf-8') as f:
        scan = json.load(f)

    domain = scan["target_info"]["domain"]
    scan_time = scan.get("scan_time", "unknown")

    # 收集所有工具结果
    tool_results = {}
    for tool_dir in sorted(os.listdir(RESULTS_DIR)):
        tpath = os.path.join(RESULTS_DIR, tool_dir)
        if not os.path.isdir(tpath): continue
        result_files = sorted(glob.glob(os.path.join(tpath, f"result_{domain}_*.json")), reverse=True)
        if result_files:
            with open(result_files[0], 'r', encoding='utf-8') as f:
                tool_results[tool_dir] = json.load(f)

    # 统计
    total_issues = len(scan.get("security_issues", []))
    critical = sum(1 for i in scan.get("security_issues", []) if i.get("severity") == "Critical")
    high = sum(1 for i in scan.get("security_issues", []) if i.get("severity") == "High")
    ports_valid = [p for p in scan.get("ports", []) if p.get("confidence") != "cdn_noise"]
    ports_noise = [p for p in scan.get("ports", []) if p.get("confidence") == "cdn_noise"]
    tool_success = sum(1 for r in tool_results.values() if r.get("status") == "success")
    tool_total = len(tool_results)

    # HTML
    html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>bee-py · {domain} 渗透测试报告</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f1f5f9;color:#1e293b;line-height:1.6}}
.header{{background:linear-gradient(135deg,#1e293b,#334155);color:#fff;padding:40px 30px;text-align:center}}
.header h1{{font-size:28px;margin-bottom:8px}}
.header .sub{{opacity:.7;font-size:14px}}
.container{{max-width:1100px;margin:0 auto;padding:20px}}
.card{{background:#fff;border-radius:12px;padding:24px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.card h2{{font-size:18px;margin-bottom:16px;border-bottom:2px solid #e2e8f0;padding-bottom:8px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}}
.stat{{background:#fff;border-radius:10px;padding:20px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.stat .num{{font-size:36px;font-weight:700}}
.stat .label{{font-size:13px;color:#64748b;margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th{{background:#f8fafc;text-align:left;padding:10px 12px;border-bottom:2px solid #e2e8f0;font-weight:600}}
td{{padding:10px 12px;border-bottom:1px solid #f1f5f9}}
.sev{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;color:#fff}}
.tag{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;background:#e2e8f0;margin:2px}}
.tag.green{{background:#dcfce7;color:#166534}}
.tag.red{{background:#fee2e2;color:#991b1b}}
.tag.yellow{{background:#fef3c7;color:#92400e}}
.tag.blue{{background:#dbeafe;color:#1e40af}}
.footer{{text-align:center;padding:30px;color:#94a3b8;font-size:13px}}
pre{{background:#f1f5f9;padding:12px;border-radius:8px;overflow-x:auto;font-size:13px}}
</style>
</head>
<body>

<div class="header">
  <h1>🐝 bee-py 渗透测试报告</h1>
  <div class="sub">目标: {domain} · 扫描时间: {scan_time}</div>
</div>

<div class="container">

  <!-- 总览卡片 -->
  <div class="stats">
    <div class="stat"><div class="num" style="color:#dc2626">{critical}</div><div class="label">严重漏洞</div></div>
    <div class="stat"><div class="num" style="color:#ea580c">{high}</div><div class="label">高危漏洞</div></div>
    <div class="stat"><div class="num" style="color:#f59e0b">{total_issues}</div><div class="label">安全问题</div></div>
    <div class="stat"><div class="num" style="color:#6366f1">{len(ports_valid)}</div><div class="label">可信端口</div></div>
    <div class="stat"><div class="num" style="color:#10b981">{len(scan.get("directories",[]))}</div><div class="label">敏感路径</div></div>
    <div class="stat"><div class="num" style="color:#8b5cf6">{tool_success}/{tool_total}</div><div class="label">工具成功</div></div>
  </div>

  <!-- 目标信息 -->
  <div class="card">
    <h2>📋 目标信息</h2>
    <table>
      <tr><td style="width:140px;color:#64748b">域名</td><td><strong>{domain}</strong></td></tr>
      <tr><td style="color:#64748b">IP</td><td>{scan["target_info"].get("ip","N/A")}</td></tr>
      <tr><td style="color:#64748b">CDN</td><td>{scan["target_info"].get("cdn") or "直连源站"}</td></tr>
      <tr><td style="color:#64748b">子域名</td><td>{len(scan.get("subdomains",[]))} 个</td></tr>
      <tr><td style="color:#64748b">SSL</td><td>{scan.get("ssl_info",{}).get("protocol","?")} / {scan.get("ssl_info",{}).get("cipher","?")}</td></tr>
    </table>
  </div>

  <!-- 端口 -->
  <div class="card">
    <h2>🔌 开放端口</h2>
    <table>
      <tr><th>端口</th><th>服务</th><th>可信度</th><th>Banner/版本</th></tr>
'''
    for p in ports_valid[:20]:
        conf = p.get("confidence","?")
        conf_tag = {"high":"green","medium":"yellow","low":"red"}.get(conf,"")
        html += f'<tr><td>{p["port"]}</td><td>{p["service"]}</td><td><span class="tag {conf_tag}">{conf}</span></td><td style="font-size:12px">{p.get("banner","")[:60] or p.get("version","")}</td></tr>'
    if ports_noise:
        html += f'<tr><td colspan="4" style="color:#94a3b8;text-align:center">+ {len(ports_noise)} 个 CDN 噪音端口（已自动过滤）</td></tr>'

    html += '</table></div>'

    # 安全问题
    if scan.get("security_issues"):
        html += '<div class="card"><h2>⚠️ 安全问题</h2><table><tr><th>严重度</th><th>类型</th><th>路径</th><th>修复建议</th></tr>'
        for iss in scan["security_issues"][:30]:
            sev = iss.get("severity","?")
            html += f'<tr><td><span class="sev" style="background:{_sev_color(sev)}">{sev}</span></td><td>{iss.get("type","?")}</td><td style="font-size:12px">{iss.get("path","")[:60]}</td><td style="font-size:12px">{iss.get("remediation","")[:60]}</td></tr>'
        html += '</table></div>'

    # 敏感路径
    if scan.get("directories"):
        html += '<div class="card"><h2>📁 敏感路径</h2><table><tr><th>路径</th><th>状态</th></tr>'
        for d in scan["directories"][:30]:
            html += f'<tr><td style="font-size:13px">{d["path"][:80]}</td><td>{d.get("description",d.get("status",""))}</td></tr>'
        html += '</table></div>'

    # 指纹
    if scan.get("fingerprints"):
        html += '<div class="card"><h2>🔍 技术栈指纹</h2><p>'
        for fp in scan["fingerprints"]:
            html += f'<span class="tag blue">{fp.get("value","?")}</span> '
        html += '</p></div>'

    # 工具结果
    if tool_results:
        html += '<div class="card"><h2>⚔️ 工具执行结果</h2><table><tr><th>工具</th><th>状态</th><th>摘要</th></tr>'
        for tid, tr in sorted(tool_results.items()):
            st = tr.get("status","?")
            html += f'<tr><td>{tid}</td><td>{_status_icon(st)} {st}</td><td>{tr.get("summary","-")[:80]}</td></tr>'
        html += '</table></div>'

        # 详细结果（凭据部分脱敏展示）
        for tid, tr in tool_results.items():
            if tr.get("credentials"):
                html += f'<div class="card"><h2>🔑 {tid} — 凭据发现</h2><table><tr><th>服务/URL</th><th>用户名</th><th>密码</th></tr>'
                for cred in tr["credentials"][:10]:
                    html += f'<tr><td style="font-size:12px">{cred.get("target",cred.get("url",""))[:50]}</td><td>{cred.get("username","")}</td><td style="font-family:monospace">{cred.get("password","")[:8]}***</td></tr>'
                html += '</table></div>'

            if tr.get("findings"):
                html += f'<div class="card"><h2>🎯 {tid} — 漏洞发现</h2>'
                for f in tr["findings"][:10]:
                    html += f'<p style="margin-bottom:8px"><span class="tag red">{f.get("confidence","?")}</span> <strong>{f.get("url","")[:60]}</strong><br><span style="font-size:12px;color:#64748b">{f.get("detail","")}</span></p>'
                html += '</div>'

            if tr.get("endpoints"):
                html += f'<div class="card"><h2>📋 {tid} — API端点</h2><table><tr><th>方法</th><th>路径</th><th>说明</th></tr>'
                for ep in tr["endpoints"][:30]:
                    html += f'<tr><td>{ep.get("method","")}</td><td style="font-size:12px">{ep.get("path","")[:60]}</td><td style="font-size:12px">{ep.get("summary","")[:50]}</td></tr>'
                html += '</table></div>'

            if tr.get("cve_matches"):
                html += f'<div class="card"><h2>📦 {tid} — CVE匹配</h2><table><tr><th>CVE</th><th>严重度</th><th>指纹</th><th>描述</th></tr>'
                for c in tr["cve_matches"][:20]:
                    html += f'<tr><td>{c.get("cve","")}</td><td><span class="sev" style="background:{_sev_color(c.get("severity","Medium"))}">{c.get("severity","?")}</span></td><td>{c.get("fingerprint","")[:30]}</td><td style="font-size:12px">{c.get("description","")[:80]}</td></tr>'
                html += '</table></div>'

    html += f'''
</div>
<div class="footer">
  Generated by bee-py · {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
  仅供授权安全测试使用
</div>
</body></html>'''

    # 保存
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(REPORTS_DIR, f"report_{domain}_{ts}.html")
    with open(out, 'w', encoding='utf-8') as f:
        f.write(html)
    return out

def main():
    print("🐝 bee-py · HTML 报告生成器")
    path = build_report()
    if path:
        print(f"✅ 报告已生成: {path}")
        print(f"   浏览器打开: open {path}")

if __name__ == "__main__":
    main()
