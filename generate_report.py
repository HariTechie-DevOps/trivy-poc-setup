#!/usr/bin/env python3
"""
Trivy HTML Report Generator
Reads 3 Trivy JSON scan outputs and generates one HTML report
"""
import json
import os
import sys
from datetime import datetime

# ── Read arguments ────────────────────────────────────────────
def usage():
    print("Usage: python3 generate_report.py <repo.json> <fs.json> <image.json> <output.html> <app_name> <build_no> <image_name>")
    sys.exit(1)

if len(sys.argv) < 8:
    usage()

REPO_JSON   = sys.argv[1]
FS_JSON     = sys.argv[2]
IMAGE_JSON  = sys.argv[3]
OUTPUT_HTML = sys.argv[4]
APP_NAME    = sys.argv[5]
BUILD_NO    = sys.argv[6]
IMAGE_NAME  = sys.argv[7]
SCAN_TIME   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ── Load JSON safely ─────────────────────────────────────────
def load(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: could not read {path}: {e}")
        return None

# ── Count severities ─────────────────────────────────────────
def stats(data):
    s = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
    if not data:
        return s
    for r in data.get("Results", []):
        for item in (r.get("Vulnerabilities") or []) + \
                    (r.get("Misconfigurations") or []) + \
                    (r.get("Secrets") or []):
            sev = item.get("Severity", "").upper()
            if sev in s:
                s[sev] += 1
                s["total"] += 1
    return s

# ── Severity badge ────────────────────────────────────────────
def badge(sev):
    color = {
        "CRITICAL": ("#FF4444", "#fff"),
        "HIGH":     ("#FF8800", "#fff"),
        "MEDIUM":   ("#FFCC00", "#000"),
        "LOW":      ("#44BB44", "#fff"),
    }.get(sev.upper(), ("#888", "#fff"))
    return (f"<span style='background:{color[0]};color:{color[1]};"
            f"padding:2px 9px;border-radius:4px;font-size:11px;"
            f"font-weight:bold;white-space:nowrap'>{sev}</span>")

# ── Build table rows from scan data ──────────────────────────
def rows(data):
    if not data:
        return ("<tr><td colspan='6' style='text-align:center;"
                "color:#666;padding:24px'>Scan skipped / no data</td></tr>")
    html = ""
    found = False

    for r in data.get("Results", []):
        target = r.get("Target", "")

        for v in (r.get("Vulnerabilities") or []):
            found = True
            fix = v.get("FixedVersion") or "<span style='color:#666'>No fix yet</span>"
            cve = v.get("VulnerabilityID", "")
            url = v.get("PrimaryURL", "#")
            html += f"""
            <tr>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540'>
                <code style='color:#4A9EFF;font-size:11px'>{target}</code>
              </td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540'>{v.get('PkgName','')}</td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540'>
                <a href='{url}' target='_blank' style='color:#4A9EFF'>{cve}</a>
              </td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540'>{badge(v.get('Severity',''))}</td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540;color:#aaa'>{v.get('InstalledVersion','')}</td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540;color:#44BB44'>{fix}</td>
            </tr>"""

        for m in (r.get("Misconfigurations") or []):
            found = True
            html += f"""
            <tr>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540'>
                <code style='color:#4A9EFF;font-size:11px'>{target}</code>
              </td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540'>
                <span style='color:#FF8800'>Misconfiguration</span>
              </td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540;color:#FF8800'>{m.get('ID','')}</td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540'>{badge(m.get('Severity',''))}</td>
              <td colspan='2' style='padding:9px 10px;border-bottom:1px solid #1a2540;color:#ccc'>{m.get('Title','')}</td>
            </tr>"""

        for sec in (r.get("Secrets") or []):
            found = True
            html += f"""
            <tr>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540'>
                <code style='color:#4A9EFF;font-size:11px'>{target}</code>
              </td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540;color:#FF4444;font-weight:bold'>
                🔑 SECRET EXPOSED
              </td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540'>—</td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540'>{badge('CRITICAL')}</td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540;color:#aaa'>{sec.get('Category','')}</td>
              <td style='padding:9px 10px;border-bottom:1px solid #1a2540;color:#aaa'>Rule: {sec.get('RuleID','')}</td>
            </tr>"""

    if not found:
        html = ("<tr><td colspan='6' style='text-align:center;"
                "color:#44BB44;padding:24px;font-size:15px'>✅ No issues found</td></tr>")
    return html

# ── Mini stat card ────────────────────────────────────────────
def card(label, val, color):
    return (f"<div style='background:{color}18;border:2px solid {color};"
            f"border-radius:8px;padding:14px 18px;text-align:center;min-width:85px'>"
            f"<div style='font-size:26px;font-weight:bold;color:{color}'>{val}</div>"
            f"<div style='font-size:11px;color:#888;margin-top:3px'>{label}</div></div>")

# ── Section block ─────────────────────────────────────────────
def section(icon, title, st, table_rows):
    border = ("#FF4444" if st["CRITICAL"] > 0
              else "#FF8800" if st["HIGH"] > 0
              else "#44BB44")
    status = ("🔴 CRITICAL FOUND" if st["CRITICAL"] > 0
              else "🟠 HIGH FOUND" if st["HIGH"] > 0
              else "✅ CLEAN")
    status_bg = ("#FF444422" if st["CRITICAL"] > 0
                 else "#FF880022" if st["HIGH"] > 0
                 else "#44BB4422")

    return f"""
    <div style='background:#111827;border-radius:12px;padding:24px;
                margin-bottom:24px;border-left:4px solid {border}'>
      <div style='display:flex;justify-content:space-between;
                  align-items:center;margin-bottom:18px;flex-wrap:wrap;gap:10px'>
        <h2 style='color:#E0E0FF;margin:0;font-size:17px'>{icon} {title}</h2>
        <span style='background:{status_bg};color:{border};padding:4px 14px;
                     border-radius:20px;font-size:12px;font-weight:700;
                     border:1px solid {border}'>{status}</span>
      </div>
      <div style='display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px'>
        {card('CRITICAL', st['CRITICAL'], '#FF4444')}
        {card('HIGH',     st['HIGH'],     '#FF8800')}
        {card('MEDIUM',   st['MEDIUM'],   '#FFCC00')}
        {card('LOW',      st['LOW'],      '#44BB44')}
        {card('TOTAL',    st['total'],    '#4A9EFF')}
      </div>
      <div style='overflow-x:auto;border-radius:8px;border:1px solid #1a2540'>
        <table style='width:100%;border-collapse:collapse;font-size:13px'>
          <thead>
            <tr style='background:#0a1628;color:#666;font-size:11px;
                       text-transform:uppercase;letter-spacing:0.5px'>
              <th style='padding:10px;text-align:left;border-bottom:1px solid #1a2540'>Target</th>
              <th style='padding:10px;text-align:left;border-bottom:1px solid #1a2540'>Package / Type</th>
              <th style='padding:10px;text-align:left;border-bottom:1px solid #1a2540'>CVE / ID</th>
              <th style='padding:10px;text-align:left;border-bottom:1px solid #1a2540'>Severity</th>
              <th style='padding:10px;text-align:left;border-bottom:1px solid #1a2540'>Installed</th>
              <th style='padding:10px;text-align:left;border-bottom:1px solid #1a2540'>Fixed In</th>
            </tr>
          </thead>
          <tbody style='color:#C9D1D9'>{table_rows}</tbody>
        </table>
      </div>
    </div>"""

# ── Build full HTML ───────────────────────────────────────────
repo_data  = load(REPO_JSON)
fs_data    = load(FS_JSON)
image_data = load(IMAGE_JSON)

rs = stats(repo_data)
fs = stats(fs_data)
is_ = stats(image_data)

total_c = rs["CRITICAL"] + fs["CRITICAL"] + is_["CRITICAL"]
total_h = rs["HIGH"]     + fs["HIGH"]     + is_["HIGH"]
grand   = rs["total"]    + fs["total"]    + is_["total"]

oc = "#FF4444" if total_c > 0 else "#FF8800" if total_h > 0 else "#44BB44"
os_ = ("🔴 CRITICAL VULNERABILITIES FOUND" if total_c > 0
       else "🟠 HIGH VULNERABILITIES FOUND" if total_h > 0
       else "✅ ALL SCANS PASSED")

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Trivy Security Report — {APP_NAME} #{BUILD_NO}</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0 }}
    body {{
      font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background: #0d1117;
      color: #C9D1D9;
      padding: 24px;
      line-height: 1.5;
    }}
    a {{ color:#4A9EFF; text-decoration:none }}
    a:hover {{ text-decoration:underline }}
    code {{ background:#0a1628; padding:2px 6px; border-radius:4px; font-size:12px }}
    tbody tr:nth-child(even) {{ background:#0a1628 }}
    tbody tr:hover {{ background:#0f2040 }}
  </style>
</head>
<body>
<div style="max-width:1280px;margin:0 auto">

  <!-- ── HEADER ── -->
  <div style="background:linear-gradient(135deg,#111827,#0a1628);
              border-radius:14px;padding:32px;margin-bottom:24px;
              border:1px solid #1a2540">
    <div style="display:flex;justify-content:space-between;
                align-items:center;flex-wrap:wrap;gap:16px">
      <div>
        <div style="color:#4A9EFF;font-size:11px;font-weight:700;
                    letter-spacing:3px;margin-bottom:10px">
          TRIVY SECURITY SCAN REPORT
        </div>
        <h1 style="color:#E8E8FF;font-size:28px;margin-bottom:8px">
          {APP_NAME}
        </h1>
        <div style="color:#666;font-size:13px">
          Build &nbsp;<strong style="color:#aaa">#{BUILD_NO}</strong>
          &nbsp;•&nbsp;
          Image: &nbsp;<code>{IMAGE_NAME}</code>
          &nbsp;•&nbsp;
          {SCAN_TIME}
        </div>
      </div>
      <div style="background:{oc}18;border:2px solid {oc};
                  border-radius:12px;padding:18px 28px;text-align:center">
        <div style="font-size:11px;color:{oc};font-weight:700;
                    letter-spacing:1px;margin-bottom:6px">{os_}</div>
        <div style="font-size:48px;font-weight:800;color:{oc};
                    line-height:1">{grand}</div>
        <div style="font-size:11px;color:#666;margin-top:4px">Total Issues</div>
      </div>
    </div>
  </div>

  <!-- ── SUMMARY STRIP ── -->
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
              gap:14px;margin-bottom:24px">

    <div style="background:#111827;border-radius:10px;padding:18px;
                border-top:3px solid #4A9EFF">
      <div style="color:#555;font-size:10px;letter-spacing:2px;
                  margin-bottom:10px">📦 REPO SCAN</div>
      <div style="font-size:16px;font-weight:700">
        <span style="color:#FF4444">{rs['CRITICAL']} Critical</span>
        &nbsp;
        <span style="color:#FF8800">{rs['HIGH']} High</span>
      </div>
      <div style="color:#444;font-size:12px;margin-top:4px">
        {rs['total']} total issues
      </div>
    </div>

    <div style="background:#111827;border-radius:10px;padding:18px;
                border-top:3px solid #4A9EFF">
      <div style="color:#555;font-size:10px;letter-spacing:2px;
                  margin-bottom:10px">🗂️ FILESYSTEM SCAN</div>
      <div style="font-size:16px;font-weight:700">
        <span style="color:#FF4444">{fs['CRITICAL']} Critical</span>
        &nbsp;
        <span style="color:#FF8800">{fs['HIGH']} High</span>
      </div>
      <div style="color:#444;font-size:12px;margin-top:4px">
        {fs['total']} total issues
      </div>
    </div>

    <div style="background:#111827;border-radius:10px;padding:18px;
                border-top:3px solid #4A9EFF">
      <div style="color:#555;font-size:10px;letter-spacing:2px;
                  margin-bottom:10px">🐳 IMAGE SCAN</div>
      <div style="font-size:16px;font-weight:700">
        <span style="color:#FF4444">{is_['CRITICAL']} Critical</span>
        &nbsp;
        <span style="color:#FF8800">{is_['HIGH']} High</span>
      </div>
      <div style="color:#444;font-size:12px;margin-top:4px">
        {is_['total']} total issues
      </div>
    </div>

  </div>

  <!-- ── SCAN SECTIONS ── -->
  {section('📦', 'Repository Scan — Secrets · IaC Misconfigs · Dep Vulns',
           rs,  rows(repo_data))}
  {section('🗂️', 'Filesystem Scan — All Files · Configs · Secrets',
           fs,  rows(fs_data))}
  {section('🐳', 'Docker Image Scan — OS Packages · App Libraries · Secrets',
           is_, rows(image_data))}

  <!-- ── FOOTER ── -->
  <div style="text-align:center;color:#2a3a50;font-size:12px;
              padding:20px;margin-top:10px">
    Generated by <strong style="color:#4A9EFF">Trivy Security Scanner</strong>
    &nbsp;•&nbsp; {APP_NAME} Build #{BUILD_NO} &nbsp;•&nbsp; {SCAN_TIME}
  </div>

</div>
</body>
</html>"""

with open(OUTPUT_HTML, "w") as f:
    f.write(html)

print(f"✅ Report saved → {OUTPUT_HTML}")
print(f"   Repo  : C={rs['CRITICAL']} H={rs['HIGH']} M={rs['MEDIUM']} L={rs['LOW']} Total={rs['total']}")
print(f"   FS    : C={fs['CRITICAL']} H={fs['HIGH']} M={fs['MEDIUM']} L={fs['LOW']} Total={fs['total']}")
print(f"   Image : C={is_['CRITICAL']} H={is_['HIGH']} M={is_['MEDIUM']} L={is_['LOW']} Total={is_['total']}")
print(f"   Grand Total: {grand} issues found")
