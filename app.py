"""Flask Web应用 - Web漏洞扫描器"""
import json
import os
import queue
import threading
import uuid

from flask import Flask, render_template, request, jsonify, Response

from scanner.scanner import WebScanner, ScanConfig, ScanResult
from scanner.reporter import Reporter

app = Flask(__name__)
app.config["REPORTS_DIR"] = os.path.join(os.path.dirname(__file__), "reports")

# 存储扫描状态
scan_jobs = {}  # job_id -> {"status", "progress", "result", "messages"}


@app.route("/")
def index():
    """首页/仪表板"""
    return render_template("index.html", jobs=scan_jobs)


@app.route("/scan")
def scan_page():
    """新建扫描页"""
    return render_template("scan.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """启动扫描API"""
    data = request.json or {}
    target_url = data.get("url", "").strip()
    if not target_url:
        return jsonify({"error": "请输入目标URL"}), 400

    # 确保URL有协议前缀
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    config = ScanConfig(
        target_url=target_url,
        scan_type=data.get("scan_type", "all"),
        threads=int(data.get("threads", 5)),
        depth=int(data.get("depth", 2)),
        timeout=int(data.get("timeout", 10)),
    )

    job_id = str(uuid.uuid4())[:8]
    scan_jobs[job_id] = {
        "id": job_id,
        "config": config,
        "status": "running",
        "progress": [],
        "result": None,
        "vulns": [],
    }

    thread = threading.Thread(target=_run_scan, args=(job_id, config), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id})


def _run_scan(job_id, config):
    """后台执行扫描"""
    job = scan_jobs[job_id]
    scanner = WebScanner(config)

    def on_progress(msg):
        job["progress"].append(msg)

    def on_vuln(vuln):
        job["vulns"].append(vuln.to_dict())

    scanner.on_progress(on_progress)
    scanner.on_vulnerability(on_vuln)

    try:
        result = scanner.scan()
        job["result"] = result.to_dict()
        job["status"] = "finished"

        # 保存报告
        reporter = Reporter()
        report_path = reporter.save_report(result, app.config["REPORTS_DIR"])
        job["report_path"] = report_path
    except Exception as e:
        job["status"] = "error"
        job["progress"].append(f"扫描出错: {str(e)}")


@app.route("/api/scan/<job_id>")
def scan_status(job_id):
    """查询扫描状态"""
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "任务不存在"}), 404

    return jsonify({
        "id": job_id,
        "status": job["status"],
        "progress": job["progress"],
        "vulns": job["vulns"],
        "result": job["result"],
    })


@app.route("/api/scan/<job_id>/stream")
def scan_stream(job_id):
    """SSE实时推送扫描进度"""
    def generate():
        job = scan_jobs.get(job_id)
        if not job:
            yield f"data: {json.dumps({'error': '任务不存在'})}\n\n"
            return

        last_idx = 0
        last_vuln_idx = 0
        while True:
            job = scan_jobs.get(job_id, {})
            # 推送新进度消息
            progress = job.get("progress", [])
            for msg in progress[last_idx:]:
                yield f"data: {json.dumps({'type': 'progress', 'message': msg})}\n\n"
            last_idx = len(progress)

            # 推送新发现的漏洞
            vulns = job.get("vulns", [])
            for vuln in vulns[last_vuln_idx:]:
                yield f"data: {json.dumps({'type': 'vulnerability', 'data': vuln})}\n\n"
            last_vuln_idx = len(vulns)

            # 扫描完成
            if job.get("status") in ("finished", "error"):
                yield f"data: {json.dumps({'type': 'done', 'result': job.get('result')})}\n\n"
                break

            import time
            time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/report/<job_id>")
def view_report(job_id):
    """查看报告"""
    job = scan_jobs.get(job_id)
    if not job or not job.get("result"):
        return "报告不存在", 404

    result_data = job["result"]
    # 重建ScanResult对象
    result = ScanResult(
        target_url=result_data["target_url"],
        scan_type=result_data["scan_type"],
        targets_scanned=result_data["targets_scanned"],
        scan_time=result_data["scan_time"],
        started_at=result_data["started_at"],
        finished_at=result_data["finished_at"],
    )

    reporter = Reporter()
    return reporter.generate_html(result)


@app.route("/api/jobs")
def list_jobs():
    """获取所有扫描任务"""
    jobs = []
    for jid, job in scan_jobs.items():
        jobs.append({
            "id": jid,
            "target_url": job["config"].target_url,
            "scan_type": job["config"].scan_type,
            "status": job["status"],
            "vuln_count": len(job.get("vulns", [])),
            "result": job.get("result"),
        })
    # 按创建时间倒序
    jobs.reverse()
    return jsonify(jobs)


if __name__ == "__main__":
    os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)
    print("=" * 50)
    print("  Web漏洞扫描器")
    print("  访问 http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
