"""
app.py - Local VirusTotal equivalent – Flask API + web UI
Endpoints:
  POST /api/analyze   – upload file, returns {job_id}
  GET  /api/status/<job_id> – poll for results
  GET  /api/jobs      – list recent jobs
  DELETE /api/jobs/<job_id> – remove a job + its upload
"""

import os
import uuid
import json
import threading
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, render_template, abort

# ── optional persistence: keep results in a JSON file ────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR  = os.path.join(BASE_DIR, "uploads")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

for d in (UPLOAD_DIR, RESULTS_DIR):
    os.makedirs(d, exist_ok=True)

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB max upload

# In-memory job store  {job_id: job_dict}
# On startup we reload from disk so results survive a server restart.
jobs: dict = {}


def _load_results_from_disk():
    for fname in os.listdir(RESULTS_DIR):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(RESULTS_DIR, fname)) as fh:
                    job = json.load(fh)
                    jobs[job["job_id"]] = job
            except Exception:
                pass


def _persist_job(job_id: str):
    try:
        path = os.path.join(RESULTS_DIR, f"{job_id}.json")
        with open(path, "w") as fh:
            json.dump(jobs[job_id], fh, indent=2, default=str)
    except Exception:
        pass


# ── analysis pipeline ─────────────────────────────────────────────────────────

def run_analysis(job_id: str, filepath: str, duration: int):
    from scanner import scan_with_defender
    from monitor import execute_and_monitor

    try:
        # Phase 1 – static scan
        jobs[job_id]["status"]  = "scanning"
        jobs[job_id]["phase"]   = "Running Windows Defender scan…"
        _persist_job(job_id)

        scan_result = scan_with_defender(filepath)
        jobs[job_id]["scan_result"] = scan_result

        # If Defender already quarantined the file skip execution
        if scan_result.get("verdict") == "threat_detected":
            jobs[job_id]["skip_execution"] = True
            jobs[job_id]["phase"] = (
                "Threat detected during static scan – skipping live execution "
                "(file may have been quarantined by Defender). "
                "Toggle DisableRemediation in scanner.py to execute anyway."
            )

        # Phase 2 – dynamic execution
        if not jobs[job_id].get("skip_execution"):
            jobs[job_id]["status"] = "executing"
            jobs[job_id]["phase"]  = f"Executing sample and monitoring for {duration}s…"
            _persist_job(job_id)

            monitor_result = execute_and_monitor(filepath, duration)
            jobs[job_id]["monitor_result"] = monitor_result
        else:
            jobs[job_id]["monitor_result"] = None

        jobs[job_id]["status"]     = "complete"
        jobs[job_id]["phase"]      = "Done"
        jobs[job_id]["completed_at"] = datetime.now().isoformat()

    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["phase"]  = f"Internal error: {e}"

    _persist_job(job_id)


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f        = request.files["file"]
    duration = int(request.form.get("duration", 30))
    duration = max(5, min(duration, 300))   # clamp 5 – 300 s

    if f.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    job_id   = str(uuid.uuid4())
    # Prefix with job_id to avoid collisions
    safe_name = f"{job_id}_{f.filename}"
    filepath  = os.path.join(UPLOAD_DIR, safe_name)
    f.save(filepath)

    jobs[job_id] = {
        "job_id":      job_id,
        "filename":    f.filename,
        "filepath":    filepath,
        "duration":    duration,
        "status":      "queued",
        "phase":       "Queued",
        "submitted_at": datetime.now().isoformat(),
        "scan_result":  None,
        "monitor_result": None,
    }

    t = threading.Thread(
        target=run_analysis, args=(job_id, filepath, duration), daemon=True
    )
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/api/status/<job_id>")
def status(job_id: str):
    job = jobs.get(job_id)
    if not job:
        # Try loading from disk
        path = os.path.join(RESULTS_DIR, f"{job_id}.json")
        if os.path.exists(path):
            with open(path) as fh:
                job = json.load(fh)
                jobs[job_id] = job
        else:
            return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/jobs")
def list_jobs():
    summary = []
    for jid, j in sorted(jobs.items(),
                          key=lambda x: x[1].get("submitted_at", ""),
                          reverse=True):
        scan  = j.get("scan_result") or {}
        mon   = j.get("monitor_result") or {}
        risk  = mon.get("risk_score", {})
        summary.append({
            "job_id":       jid,
            "filename":     j.get("filename"),
            "status":       j.get("status"),
            "submitted_at": j.get("submitted_at"),
            "verdict":      scan.get("verdict"),
            "risk_level":   risk.get("level"),
            "risk_score":   risk.get("score"),
        })
    return jsonify(summary[:50])   # last 50


@app.route("/api/jobs/<job_id>", methods=["DELETE"])
def delete_job(job_id: str):
    job = jobs.pop(job_id, None)
    if job:
        try:
            os.remove(job["filepath"])
        except Exception:
            pass
        try:
            os.remove(os.path.join(RESULTS_DIR, f"{job_id}.json"))
        except Exception:
            pass
        return jsonify({"deleted": job_id})
    return jsonify({"error": "Not found"}), 404


# ── startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _load_results_from_disk()
    print("=" * 60)
    print("  Local Malware Sandbox")
    print("  http://localhost:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
