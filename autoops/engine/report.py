"""
AutoSecOps — Report Engine
Generates HTML and JSON reports from scan results.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AutoSecOps — Scan Report</title>
  <style>
    :root {
      --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
      --border: #30363d; --text: #e6edf3; --muted: #8b949e;
      --accent: #58a6ff; --success: #3fb950; --warning: #d29922; --danger: #f85149;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 32px; line-height: 1.6; }
    .header { text-align: center; margin-bottom: 32px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }
    .header h1 { font-size: 24px; margin-bottom: 6px; }
    .meta { color: var(--muted); font-size: 13px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-bottom: 32px; }
    .stat { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
    .stat-value { font-size: 28px; font-weight: 700; }
    .stat-label { font-size: 12px; color: var(--muted); margin-top: 2px; }
    .critical .stat-value { color: var(--danger); }
    .high .stat-value { color: var(--warning); }
    .medium .stat-value { color: #e3b341; }
    .low .stat-value { color: var(--success); }
    .section { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
    .section-title { padding: 14px 20px; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); color: var(--muted); }
    .finding { padding: 14px 20px; border-bottom: 1px solid var(--border); }
    .finding:last-child { border-bottom: none; }
    .finding-head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: rgba(248,81,73,0.15); color: var(--danger); }
    .badge-high { background: rgba(210,153,34,0.15); color: var(--warning); }
    .badge-medium { background: rgba(227,179,65,0.15); color: #e3b341; }
    .badge-low { background: rgba(63,185,80,0.15); color: var(--success); }
    .badge-info { background: rgba(88,166,255,0.15); color: var(--accent); }
    .finding-rule { font-weight: 600; font-size: 14px; }
    .finding-file { font-size: 12px; color: var(--muted); margin-top: 4px; font-family: monospace; }
    .finding-msg { font-size: 13px; color: var(--muted); margin-top: 6px; }
    .code { background: var(--bg3); border-radius: 4px; padding: 8px 12px; font-family: monospace; font-size: 12px; color: #79c0ff; margin-top: 6px; overflow-x: auto; }
    .footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 32px; }
    table { width: 100%; border-collapse: collapse; }
    th { background: var(--bg3); color: var(--muted); font-size: 12px; text-align: left; padding: 10px 16px; border-bottom: 1px solid var(--border); }
    td { padding: 10px 16px; font-size: 13px; border-bottom: 1px solid var(--border); }
    tr:last-child td { border-bottom: none; }
  </style>
</head>
<body>
<div style="max-width: 900px; margin: 0 auto;">
  <div class="header">
    <h1>🛡️ AutoSecOps — Security Scan Report</h1>
    <p class="meta">Generated: {generated_at} &nbsp;|&nbsp; Scan ID: {scan_id} &nbsp;|&nbsp; Target: {target}</p>
  </div>

  <div class="stats">
    <div class="stat critical"><div class="stat-value">{critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat high"><div class="stat-value">{high}</div><div class="stat-label">High</div></div>
    <div class="stat medium"><div class="stat-value">{medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat low"><div class="stat-value">{low}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-value">{total}</div><div class="stat-label">Total</div></div>
  </div>

  {sections}

  <div class="footer">
    <p>AutoSecOps — Automated Ops & Security Platform &copy; 2025</p>
    <p>This report is generated automatically. Verify all findings manually before taking action.</p>
  </div>
</div>
</body>
</html>
"""

def _badge(sev):
    return f'<span class="badge badge-{sev}">{sev.upper()}</span>'

def _severity_div(data, key, title, icon=""):
    items = data.get(key, [])
    if not items:
        return ""
    rows = []
    for item in items[:50]:  # Cap at 50 for readability
        rule_id = item.get("rule_id", item.get("vuln_id", item.get("id", "")))
        sev = item.get("severity", "info")
        title_txt = item.get("title", item.get("title", ""))
        file_txt = item.get("file", item.get("target", "")) + (f":{item['line']}" if item.get("line") else "")
        msg = item.get("message", item.get("description", ""))[:200]
        code = item.get("code_snippet", "")
        rows.append(f"""
        <div class="finding">
          <div class="finding-head">
            {_badge(sev)}
            <span class="finding-rule">{rule_id} — {icon}{title_txt}</span>
          </div>
          <div class="finding-file">{file_txt}</div>
          {f'<div class="code">{code}</div>' if code else ""}
          <div class="finding-msg">{msg}</div>
        </div>
        """)
    return f"""
    <div class="section">
      <div class="section-title">{title} ({len(items)})</div>
      {"".join(rows)}
    </div>
    """


class ReportEngine:
    """
    Generate HTML or JSON scan reports.
    """

    def __init__(self, output_dir: str | Path = "autoops-reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)

    def generate_html(self, scan_id: str, data: dict[str, Any]) -> Path:
        """Generate a standalone HTML report."""
        summary = data.get("summary", {})
        total = summary.get("total", 0)
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)

        sections = ""
        sast = data.get("sast_findings", [])
        dep = data.get("dep_findings", [])
        secret = data.get("secret_findings", [])
        container = data.get("container_findings", [])

        if sast:
            sections += _severity_div({"sast": sast}, "sast", "🔬 SAST Findings", "")
        if dep:
            sections += _severity_div({"dep": dep}, "dep", "📦 Dependency Vulnerabilities", "")
        if secret:
            sections += _severity_div({"secret": secret}, "secret", "🔑 Secret Findings", "")
        if container:
            sections += _severity_div({"container": container}, "container", "📦 Container Vulnerabilities", "")

        html = HTML_TEMPLATE.format(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            scan_id=scan_id,
            target=data.get("target", ""),
            total=total,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            sections=sections or "<p style='padding:20px;color:var(--muted)'>No findings.</p>",
        )

        out_path = self.output_dir / f"{scan_id}_report.html"
        out_path.write_text(html, encoding="utf-8")
        return out_path

    def generate_json(self, scan_id: str, data: dict[str, Any]) -> Path:
        """Generate a JSON report."""
        out_path = self.output_dir / f"{scan_id}_report.json"
        out_path.write_text(
            json.dumps({**data, "generated_at": datetime.now().isoformat()}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return out_path

    def generate(self, scan_id: str, data: dict[str, Any]) -> dict[str, Path]:
        """Generate both HTML and JSON reports."""
        return {
            "html": self.generate_html(scan_id, data),
            "json": self.generate_json(scan_id, data),
        }
