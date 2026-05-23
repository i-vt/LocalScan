# LocalScan — Local Malware Analysis Sandbox
<img width="3840" height="1926" alt="image" src="https://github.com/user-attachments/assets/2fe525af-f4d5-43be-b8f7-2269df111a07" />
<img width="3840" height="1926" alt="image" src="https://github.com/user-attachments/assets/3d462988-dde5-4c27-8f49-6cf47a5f1516" />

A self-hosted, VirusTotal-style malware analysis sandbox for blue teamers. Upload a sample, get a static Windows Defender verdict, watch it execute for N seconds, and receive a full report of every process spawned, network connection opened, and Defender alert fired — all through a web UI.

> **Designed for an isolated VirtualBox VM only. Never run on a production machine.**

---

## Features

- **Static scan** via Windows Defender (`MpCmdRun.exe`) with `-DisableRemediation` so the file is flagged but not quarantined before execution
- **Dynamic execution monitoring** — polls every 0.5 s for new processes (full command line + parent PID), new network connections (local/remote addr, status, PID), and Defender/Sysmon event log deltas
- **Configurable duration** — 5 to 300 seconds via the UI slider or `duration` API parameter
- **Risk scoring** — 0–100 score (Clean / Low / Medium / High / Critical) based on Defender alerts, suspicious child processes, and network activity
- **Sysmon integration** — automatically reads the Sysmon Operational log if Sysmon is installed, giving DNS queries, file drops, and richer process telemetry
- **Job persistence** — results survive a server restart (stored as JSON in `results\`)
- **Job queue** — add a one-line semaphore (see [Concurrent Submissions](#concurrent-submissions)) to serialise analyses and prevent cross-contamination
- **Web UI** — dark-theme interface with drag-and-drop upload, live status polling, collapsible result sections, hash copy buttons, and a history view

---

## Architecture

```
LocalScan\
├── setup.ps1          # One-shot VM provisioning script (run as Admin)
├── app.py             # Flask API + job runner
├── scanner.py         # Windows Defender static scan wrapper
├── monitor.py         # Dynamic execution monitor
├── requirements.txt   # Python dependencies
├── templates\
│   └── index.html     # Web UI (single-page, vanilla JS)
├── uploads\           # Uploaded samples (created by setup.ps1)
├── results\           # JSON result files (created by setup.ps1)
└── logs\
    └── server.log     # Flask + server stdout
```

### Request flow

```
Browser  ──POST /api/analyze──►  app.py  ──► scanner.py  (MpCmdRun.exe)
                                         ──► monitor.py  (Popen + psutil loop)
Browser  ──GET  /api/status/<id>──► app.py  (returns live job dict)
```

---

## Requirements

| Requirement | Notes |
|---|---|
| Windows 10 / 11 (x64) | VM only |
| Windows Defender enabled | Real-time protection should stay **on** |
| Python 3.10+ | Installed automatically by `setup.ps1` via `winget` |
| Administrator rights | Required for `setup.ps1`, audit policy, firewall rules |
| Internet access (first run) | To download Python, Sysmon, and pip packages |
| Sysmon | Optional but recommended — installed automatically by `setup.ps1` |

---

## Setup

**1. Copy all files into a single folder on the VM** (shared folder, RDP paste, ISO, etc.):

```
setup.ps1
app.py
scanner.py
monitor.py
requirements.txt
templates\index.html
```

**2. Open PowerShell as Administrator, navigate to that folder, and run:**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\setup.ps1
```

`setup.ps1` will:

1. Install Python 3.11 via `winget` if not already present
2. Create `C:\MalwareAnalysis\` with `uploads\`, `results\`, `templates\`, `logs\`
3. Copy all source files into place
4. Run `pip install` for Flask, psutil, and pywin32
5. Configure Defender — cloud reporting off, `uploads\` excluded from auto-quarantine
6. Enable process creation auditing (Event ID 4688 with command-line logging)
7. Download and install Sysmon with a baseline config (process create, network, DNS, file drops)
8. Add a Windows Firewall inbound rule for TCP 5000
9. Create a Scheduled Task that starts the server at every login (hidden window, elevated)
10. Place a `LocalScan` shortcut on the Public Desktop
11. Launch the server immediately in a new PowerShell window

**3. Open the UI:**

```
http://localhost:5000
```

---

## Usage

### Web UI

1. Drag and drop a file onto the upload zone (or click to browse). Max 64 MB.
2. Adjust the **Monitor Duration** slider (default 30 s).
3. Click **Analyze**.
4. The status bar shows the current phase. When complete, results expand below.

### REST API

**Submit a sample**

```http
POST /api/analyze
Content-Type: multipart/form-data

file=<binary>
duration=30
```

Response:

```json
{ "job_id": "3f2a1b4c-..." }
```

**Poll for results**

```http
GET /api/status/<job_id>
```

The `status` field progresses through: `queued` → `scanning` → `executing` → `complete` (or `error`).

**List recent jobs**

```http
GET /api/jobs
```

Returns up to 50 jobs summarised (filename, status, AV verdict, risk level/score).

**Delete a job**

```http
DELETE /api/jobs/<job_id>
```

Removes the job record and deletes the uploaded file.

---

## Result structure

A complete job object looks like this:

```json
{
  "job_id": "...",
  "filename": "sample.exe",
  "status": "complete",
  "scan_result": {
    "verdict": "threat_detected",
    "threats": ["Trojan:Win32/Wacatac.B!ml"],
    "hashes": { "md5": "...", "sha1": "...", "sha256": "..." },
    "filesize": 49152,
    "magic": "4D5A900003000000"
  },
  "monitor_result": {
    "new_processes": [
      { "pid": 4821, "name": "cmd.exe", "cmdline": "cmd.exe /c whoami", "ppid": 4800, "time": 1.5 }
    ],
    "new_connections": [
      { "laddr": "192.168.1.10:49231", "raddr": "93.184.216.34:443", "status": "ESTABLISHED", "pid": 4800, "time": 3.2 }
    ],
    "defender_alerts": [],
    "sysmon_alerts": [...],
    "timeline": [...],
    "risk_score": { "score": 42, "level": "medium", "reasons": ["Spawned 1 new process(es)", "Suspicious child processes: cmd.exe", "Opened 1 network connection(s)"] }
  }
}
```

---

## Concurrent submissions

The server accepts multiple simultaneous uploads, but running more than one sample at a time causes monitoring cross-contamination (process and network events bleed between jobs). Add a serialisation semaphore in `app.py` to queue analyses:

```python
# app.py -- add near the top, after imports
_analysis_lock = threading.Semaphore(1)

# Wrap the body of run_analysis() with:
def run_analysis(job_id, filepath, duration):
    jobs[job_id]["status"] = "queued"
    jobs[job_id]["phase"]  = "Waiting for previous analysis to finish..."
    _persist_job(job_id)

    with _analysis_lock:
        # ... existing function body unchanged ...
```

All submissions get a `job_id` immediately; the UI polls and shows the waiting state automatically.

---

## Operational security

> This sandbox is a **detection and triage tool**, not a hardened containment environment. Treat every analysis session as potentially contaminating the VM.

- **Snapshot before, restore after.** Take a clean VirtualBox snapshot before any analysis session. Restore it afterwards — do not reuse a VM that has executed malware.
- **Network isolation.** The VM should have **no route to the internet or your production network** during execution. Use a host-only or isolated NAT adapter. The sandbox itself only needs port 5000 reachable from your analysis workstation.
- **Defender stays on.** The setup intentionally leaves real-time protection enabled. Do not disable it — firing Defender alerts is part of what we are measuring.
- **Uploads folder is excluded from auto-quarantine.** This is required so samples can be both scanned and executed. Do not add other sensitive paths to this exclusion.
- **Elevated execution.** Samples run with the same privileges as the server process (the Scheduled Task runs elevated). Assume kernel-level compromise is possible for sophisticated samples; restore the snapshot regardless of apparent behaviour.
- **Logs.** Server output is written to `C:\MalwareAnalysis\logs\server.log`. Result JSON files persist in `results\` across reboots but are wiped on snapshot restore.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `setup.ps1` parse error on first run | Script saved without UTF-8 BOM | Re-download; ensure the file is not re-saved by Notepad in ANSI mode |
| `MpCmdRun.exe not found` | Defender disabled or non-standard install path | Re-enable Defender; `scanner.py` searches both the static path and `ProgramData\Microsoft\Windows Defender\Platform\` |
| Scan returns `return_code -2147023895` | File locked by another process | Wait a moment and resubmit |
| No processes appear in results | Process auditing not enabled | Re-run `setup.ps1` or manually run `auditpol /set /subcategory:"Process Creation" /success:enable` |
| Sysmon events missing | Sysmon not installed | Run `setup.ps1` (it will install Sysmon), or install manually and re-run with `-i localscan.xml` |
| Server not reachable from host | Firewall rule missing | Re-run `setup.ps1`, or manually add an inbound TCP 5000 rule in Windows Defender Firewall |
| `pip install` fails | No internet / winget proxy | Download wheels manually and install with `pip install --no-index --find-links=. -r requirements.txt` |

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| [Flask](https://flask.palletsprojects.com/) | >= 3.0 | HTTP API and template serving |
| [psutil](https://github.com/giampaolo/psutil) | >= 5.9 | Process and network connection snapshots |
| [pywin32](https://github.com/mhammond/pywin32) | >= 306 | Windows API access (used by wevtutil wrapper) |

All installed automatically by `setup.ps1`.
