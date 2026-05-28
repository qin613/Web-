"""HTML报告生成器"""
import html
import os
from datetime import datetime

from .scanner import ScanResult


class Reporter:
    """HTML报告生成器"""

    SEVERITY_COLORS = {
        "high": "#dc3545",
        "medium": "#fd7e14",
        "low": "#ffc107",
        "info": "#0dcaf0",
    }

    SEVERITY_LABELS = {
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息",
    }

    def generate_html(self, result: ScanResult) -> str:
        """生成HTML报告"""
        vuln_rows = ""
        for i, vuln in enumerate(result.vulnerabilities, 1):
            d = vuln.to_dict()
            color = self.SEVERITY_COLORS.get(d.get("severity", "info"), "#6c757d")
            label = self.SEVERITY_LABELS.get(d.get("severity", "info"), "未知")
            vuln_type = d.get("type", "未知")
            technique = d.get("technique", "")

            vuln_rows += f"""
            <tr>
                <td>{i}</td>
                <td><span class="badge" style="background:{color};color:#fff">{label}</span></td>
                <td>{html.escape(vuln_type)}<br><small class="text-muted">{html.escape(technique)}</small></td>
                <td><code>{html.escape(d.get('url', ''))}</code></td>
                <td><code>{html.escape(d.get('param', ''))}</code> ({html.escape(d.get('method', ''))})</td>
                <td><code class="payload">{html.escape(d.get('payload', ''))}</code></td>
                <td><small>{html.escape(d.get('evidence', ''))}</small></td>
            </tr>
            """

        if not vuln_rows:
            vuln_rows = '<tr><td colspan="7" class="text-center text-muted py-4">未发现漏洞</td></tr>'

        high = sum(1 for v in result.vulnerabilities if v.severity == "high")
        medium = sum(1 for v in result.vulnerabilities if v.severity == "medium")
        low = sum(1 for v in result.vulnerabilities if v.severity in ("low", "info"))

        report = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>漏洞扫描报告 - {html.escape(result.target_url)}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#f5f7fa; color:#333; line-height:1.6; }}
.container {{ max-width:1200px; margin:0 auto; padding:20px; }}
.header {{ background:linear-gradient(135deg, #1a1a2e, #16213e); color:#fff; padding:30px; border-radius:12px; margin-bottom:24px; }}
.header h1 {{ font-size:24px; margin-bottom:8px; }}
.header .meta {{ opacity:0.8; font-size:14px; }}
.summary {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:16px; margin-bottom:24px; }}
.card {{ background:#fff; border-radius:10px; padding:20px; box-shadow:0 2px 8px rgba(0,0,0,0.06); }}
.card .number {{ font-size:32px; font-weight:700; }}
.card .label {{ font-size:14px; color:#666; margin-top:4px; }}
.card.high .number {{ color:#dc3545; }}
.card.medium .number {{ color:#fd7e14; }}
.card.low .number {{ color:#ffc107; }}
.card.total .number {{ color:#333; }}
.card.time .number {{ color:#0d6efd; font-size:24px; }}
table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:10px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,0.06); }}
th {{ background:#f8f9fa; padding:12px 16px; text-align:left; font-size:13px; color:#666; border-bottom:2px solid #dee2e6; }}
td {{ padding:12px 16px; border-bottom:1px solid #eee; font-size:13px; vertical-align:top; word-break:break-all; }}
tr:hover {{ background:#f8f9fa; }}
.badge {{ padding:3px 10px; border-radius:20px; font-size:12px; font-weight:600; }}
code {{ background:#f1f3f5; padding:2px 6px; border-radius:4px; font-size:12px; }}
code.payload {{ display:inline-block; max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.section {{ background:#fff; border-radius:10px; padding:24px; margin-bottom:24px; box-shadow:0 2px 8px rgba(0,0,0,0.06); }}
.section h2 {{ font-size:18px; margin-bottom:16px; padding-bottom:12px; border-bottom:2px solid #eee; }}
.footer {{ text-align:center; padding:20px; color:#999; font-size:13px; }}
.text-muted {{ color:#999; }}
.no-vuln {{ text-align:center; padding:40px; color:#28a745; font-size:18px; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Web漏洞扫描报告</h1>
        <div class="meta">
            目标: {html.escape(result.target_url)} |
            扫描时间: {html.escape(result.started_at)} ~ {html.escape(result.finished_at)} |
            扫描类型: {html.escape(result.scan_type)}
        </div>
    </div>

    <div class="summary">
        <div class="card total">
            <div class="number">{len(result.vulnerabilities)}</div>
            <div class="label">漏洞总数</div>
        </div>
        <div class="card high">
            <div class="number">{high}</div>
            <div class="label">高危漏洞</div>
        </div>
        <div class="card medium">
            <div class="number">{medium}</div>
            <div class="label">中危漏洞</div>
        </div>
        <div class="card low">
            <div class="number">{low}</div>
            <div class="label">低危/信息</div>
        </div>
        <div class="card time">
            <div class="number">{result.scan_time:.1f}s</div>
            <div class="label">扫描耗时</div>
        </div>
    </div>

    <div class="section">
        <h2>漏洞详情</h2>
        {"<div class='no-vuln'>未发现漏洞，目标看起来是安全的</div>" if not result.vulnerabilities else ""}
        {"<table>" if result.vulnerabilities else ""}
        {"<thead><tr><th>#</th><th>级别</th><th>类型</th><th>URL</th><th>参数</th><th>Payload</th><th>证据</th></tr></thead>" if result.vulnerabilities else ""}
        {"<tbody>" + vuln_rows + "</tbody>" if result.vulnerabilities else ""}
        {"</table>" if result.vulnerabilities else ""}
    </div>

    <div class="footer">
        Web漏洞扫描器 - 生成于 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    </div>
</div>
</body>
</html>"""
        return report

    def save_report(self, result: ScanResult, output_dir: str = ".") -> str:
        """保存报告到文件"""
        report_html = self.generate_html(result)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.html"
        filepath = os.path.join(output_dir, filename)
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_html)
        return filepath
