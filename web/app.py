"""
AutoSecOps Web UI — Flask Application
"""

import os
import uuid
import json
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, render_template, request, jsonify,
    send_file, abort, redirect, url_for
)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB max upload

# ── Data paths ──────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.parent
SCAN_RESULTS_DIR = BASE_DIR / "autoops-reports"
SCAN_RESULTS_DIR.mkdir(exist_ok=True)

# In-memory scan registry (replace with DB in production)
_scans: dict = {}

# ── Helpers ─────────────────────────────────────────────────────────────────

def _scan_record(scan_id: str) -> dict:
    return _scans.get(scan_id) or abort(404)

def _new_scan(scan_type: str, target: str, options: dict) -> dict:
    scan_id = str(uuid.uuid4())[:8]
    record = {
        "id": scan_id,
        "type": scan_type,
        "target": target,
        "status": "pending",
        "created_at": datetime.now().isoformat(),
        "started_at": None,
        "finished_at": None,
        "summary": None,
        "options": options,
    }
    _scans[scan_id] = record
    return record

def _finish_scan(scan_id: str, status: str, summary: dict):
    rec = _scans[scan_id]
    rec["status"] = status
    rec["finished_at"] = datetime.now().isoformat()
    rec["summary"] = summary

# ── Routes — Pages ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html", scans=_scans)

@app.route("/scan")
def scan_page():
    return render_template("scan.html")

@app.route("/history")
def history_page():
    return render_template("history.html", scans=_scans)

@app.route("/report/<scan_id>")
def report_page(scan_id):
    rec = _scan_record(scan_id)
    return render_template("report.html", scan=rec)

# ── Routes — API ─────────────────────────────────────────────────────────────

@app.route("/api/scans", methods=["POST"])
def api_create_scan():
    """Kick off a new scan."""
    data = request.get_json() or {}
    scan_type = data.get("type", "full")
    target = data.get("target", "")

    if not target:
        return jsonify({"error": "target is required"}), 400

    options = {
        "languages": data.get("languages", ["python", "go", "javascript"]),
        "fail_on": data.get("fail_on", "medium"),
        "exclude_paths": data.get("exclude_paths", []),
        "scanner": data.get("scanner", "trivy"),
    }

    record = _new_scan(scan_type, target, options)

    # ── Real implementation: dispatch to scanner subprocess ────────────────
    # from autoops.scanner import run_scan
    # run_scan.delay(record["id"], scan_type, target, options)
    # ── Placeholder: simulate async completion ─────────────────────────────
    import threading, time, random
    def _simulate():
        time.sleep(random.uniform(1, 3))
        _finish_scan(record["id"], "completed", {
            "sast": {"total": random.randint(0, 8), "critical": 0, "high": random.randint(0, 2)},
            "dep":  {"total": random.randint(0, 5), "critical": random.randint(0, 1)},
            "secret": {"total": random.randint(0, 3)},
            "container": {"total": random.randint(0, 4), "critical": 0},
        })
    threading.Thread(target=_simulate, daemon=True).start()

    return jsonify({"scan_id": record["id"], "status": "pending"}), 202

@app.route("/api/scans")
def api_list_scans():
    return jsonify(list(_scans.values()))

@app.route("/api/scans/<scan_id>")
def api_get_scan(scan_id):
    return jsonify(_scan_record(scan_id))

@app.route("/api/scans/<scan_id>/cancel", methods=["POST"])
def api_cancel_scan(scan_id):
    rec = _scan_record(scan_id)
    if rec["status"] not in ("pending", "running"):
        return jsonify({"error": "scan is not cancellable"}), 409
    rec["status"] = "cancelled"
    rec["finished_at"] = datetime.now().isoformat()
    return jsonify({"scan_id": scan_id, "status": "cancelled"})

@app.route("/api/scans/<scan_id>/report")
def api_scan_report(scan_id):
    rec = _scan_record(scan_id)
    if rec["status"] != "completed":
        return jsonify({"error": "scan not completed"}), 409

    # In production, read from SCAN_RESULTS_DIR / scan_id / summary.json
    return jsonify({
        "scan_id": scan_id,
        "generated_at": datetime.now().isoformat(),
        "summary": rec["summary"],
        "type": rec["type"],
        "target": rec["target"],
    })

@app.route("/api/scans/<scan_id>/report/download")
def api_download_report(scan_id):
    rec = _scan_record(scan_id)
    if rec["status"] != "completed":
        abort(409)

    # Placeholder: generate a JSON report on the fly
    report_path = SCAN_RESULTS_DIR / f"{scan_id}_report.json"
    report_data = {
        "scan_id": scan_id,
        "type": rec["type"],
        "target": rec["target"],
        "status": rec["status"],
        "summary": rec["summary"],
        "generated_at": datetime.now().isoformat(),
    }
    report_path.write_text(json.dumps(report_data, indent=2, ensure_ascii=False))
    return send_file(report_path, as_attachment=True, download_name=f"scan_{scan_id}_report.json")

# ── Health ───────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "0.1.0"})

# ── Error handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", message="Internal server error"), 500

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
