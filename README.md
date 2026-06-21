# LocalScan — Local Malware Analysis Sandbox
<img width="3840" height="1926" alt="image" src="https://github.com/user-attachments/assets/2fe525af-f4d5-43be-b8f7-2269df111a07" />
<img width="3840" height="1926" alt="image" src="https://github.com/user-attachments/assets/3d462988-dde5-4c27-8f49-6cf47a5f1516" />

A self-hosted malware analysis platform for isolated Windows VMs. Upload a sample and choose your mode:

- **Sandbox** — static Defender scan followed by live execution monitoring. Every process spawned, network connection opened, and Defender alert fired is captured and scored.
- **Signature Analysis** — binary-searches the exact bytes that trigger Defender, maps them to PE sections, extracts strings, measures entropy, identifies load-bearing bytes, and generates YARA rules with wildcard positions. No execution required.

> **Designed for an isolated VirtualBox VM only. Never run on a production machine.**

---

## Features

### Both modes
- Static scan via `MpCmdRun.exe` with `-DisableRemediation` (file flagged but not quarantined)
- MD5 / SHA-1 / SHA-256 hashes and magic bytes
- Job persistence — results survive a server restart (JSON in `results\`)
- Dark-theme web UI with drag-and-drop upload, live status polling, hash copy buttons, and history view
- REST API for scripted workflows

### Sandbox mode
- Dynamic execution monitoring — polls every 0.5 s for new processes (full command line + parent PID), new network connections (local/remote addr, status, PID), and Defender/Sysmon event log deltas
- Configurable monitor duration — 5 to 300 seconds
- Risk scoring — 0–100 score (Clean / Low / Medium / High / Critical) weighted by Defender alerts, suspicious child processes, and network connections
- Sysmon integration — reads the Sysmon Operational log if installed, adding DNS queries, file drops, and richer process telemetry

### Signature Analysis mode
- Binary search — finds the smallest file prefix that Defender flags, converging in `ceil(log₂(file_size))` scans
- Sensitivity analysis — flips each byte in the offending region individually; bytes whose flip clears the detection are marked load-bearing
- YARA rule generation — load-bearing positions keep their actual hex values; all other positions become `??` wildcards
- Entropy — Shannon entropy of the flagged region with an automatic annotation (high = encrypted/compressed, low = plaintext strings)
- String extraction — ASCII and UTF-16LE strings of 4+ characters from the flagged region
- PE section mapping — correlates the hit offset with the binary's section table (`.text`, `.rdata`, etc.)
- Multi-signature detection — patches each hit out of a working copy and re-runs until the file is clean
- Outputs a patched binary and a `.yar` file, both downloadable from the UI

---

## Architecture

```
local_scan\
├── setup.ps1              # One-shot VM provisioning (run as Admin)
├── app.py                 # Flask API + dual-mode job runner
├── scanner.py             # Defender static scan wrapper
├── monitor.py             # Dynamic execution monitor (sandbox mode)
├── defender_check\        # Signature analysis package
│   ├── models.py          # Hit, Report dataclasses + ScanResult constants
│   ├── scanner.py         # MpCmdRun discovery (registry, static, platform dir)
│   ├── analysis.py        # Entropy, string extraction, PE section, hex dump
│   ├── search.py          # Binary search + byte sensitivity analysis
│   ├── yara_gen.py        # YARA rule generation
│   ├── orchestrator.py    # Full signature analysis pipeline
│   └── cli.py             # Standalone CLI (python -m defender_check)
├── requirements.txt
├── requirements-dev.txt   # Adds pytest for the defender_check unit tests
├── templates\
│   └── index.html         # Web UI — vanilla JS, two-mode
├── tests\                 # 226 unit tests for the defender_check package
├── uploads\               # Uploaded samples (Defender-excluded from quarantine)
├── results\               # JSON result files + patched binaries + YARA files
├── tmp\                   # Defender-excluded temp dir used by signature analysis
└── logs\
    └── server.log
```

### Request flow

```
Browser  ──POST /api/analyze (mode=sandbox)────►  app.py ──► scanner.py  (MpCmdRun.exe)
                                                           ──► monitor.py  (Popen + psutil loop)

Browser  ──POST /api/analyze (mode=signature)──►  app.py ──► scanner.py  (initial verdict)
                                                           ──► defender_check.orchestrator

Browser  ──GET  /api/status/<id>───────────────►  app.py  (live job dict)
```

---

## Requirements

| Requirement | Notes |
|---|---|
| Windows 10 / 11 (x64) | VM only |
| Windows Defender enabled | Service must be running; `setup.ps1` verifies this |
| Python 3.10+ | Installed automatically by `setup.ps1` via `winget` |
| Administrator rights | Required for `setup.ps1`, audit policy, firewall rules |
| Internet access (first run) | To download Python, Sysmon, and pip packages |
| Sysmon | Optional but recommended — installed automatically by `setup.ps1` |

---

## Setup

**1. Copy the entire folder to the VM** (shared folder, RDP paste, ISO, etc.). The folder must contain:

```
setup.ps1
app.py
scanner.py
monitor.py
requirements.txt
requirements-dev.txt
templates\index.html
defender_check\        (the whole package folder)
```

**2. Open PowerShell as Administrator, navigate to that folder, and run:**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\setup.ps1
```

`setup.ps1` will:

1. Verify Windows Defender is running (exits with an error if not)
2. Install Python 3.11 via `winget` if not already present
3. Create `C:\MalwareAnalysis\` with `uploads\`, `results\`, `templates\`, `logs\`, `tmp\`, `defender_check\`
4. Copy all source files into place, including the `defender_check\` package
5. Run `pip install` for all dependencies
6. Configure Windows Defender for dual-mode operation (see [Defender Configuration](#defender-configuration))
7. Enable process creation auditing (Event ID 4688 with command-line logging)
8. Download and install Sysmon with a baseline config
9. Add a Windows Firewall inbound rule for TCP 5000
10. Create a launcher script that sets `TMPDIR` to `tmp\` before starting Python
11. Create a Scheduled Task that runs the server at every login (hidden window, elevated)
12. Place a `LocalScan` shortcut on the Public Desktop
13. Launch the server immediately in a new PowerShell window

**3. Open the UI:**

```
http://localhost:5000
```

---

## Defender Configuration

`setup.ps1` applies the following settings. The reasoning for each is documented in the script.

| Setting | Value | Reason |
|---|---|---|
| Real-time protection | **ON** | Sandbox mode depends on this to fire runtime alerts |
| Behavioral monitoring | **ON** | Catches in-memory and fileless techniques |
| Script scanning | **ON** | Catches PowerShell / JS / VBScript payloads |
| Cloud / MAPS reporting | **OFF** | Samples must never be uploaded to Microsoft |
| Sample submission | **OFF** | Same reason |
| Block at first sight | **OFF** | Requires cloud, which is disabled |
| Network protection | **OFF** | We want to observe the full network behaviour of samples; isolation is enforced at the hypervisor instead |
| Controlled folder access | **OFF** | Would block file-drop behaviour from being observed |
| **Excluded paths** | `uploads\` `results\` `tmp\` | See below |

### Why `tmp\` is excluded

Signature analysis writes hundreds of partial file slices to a temp directory during the binary search. With real-time protection scanning those files, Defender can quarantine a slice the instant it is written — before `MpCmdRun.exe` gets to scan it — corrupting the binary search results. Excluding only `tmp\` lets real-time protection stay fully on everywhere else.

The launcher script sets `TMPDIR`, `TMP`, and `TEMP` to `C:\MalwareAnalysis\tmp\` before starting Python, so every temp directory created by the signature analyser lands in the excluded path.

> **Do not manually disable real-time protection.** Both modes are designed to work with it on.

---

## Usage

### Web UI

1. Drag and drop a file (or click to browse). Max 64 MB.
2. Select a mode:
   - **Sandbox Analysis** — set the monitor duration (5–300 s) and click Analyze.
   - **Signature Analysis** — optionally check *Skip sensitivity analysis* for faster results (no per-byte detail or YARA wildcards), then click Analyze.
3. The status bar shows the current phase. Signature analysis may take several minutes on large files.
4. When complete, results expand below. Signature mode shows a collapsible card per hit with offset, entropy, strings, load-bearing bytes, hex dump, and YARA rule. Patched binary and YARA file can be downloaded directly from the UI.

### REST API

**Submit a sample**

```http
POST /api/analyze
Content-Type: multipart/form-data

file=<binary>
mode=sandbox          # or: signature
duration=30           # sandbox only; ignored in signature mode
no_sensitivity=false  # signature only; set true to skip per-byte analysis
```

Response:

```json
{ "job_id": "3f2a1b4c-..." }
```

**Poll for results**

```http
GET /api/status/<job_id>
```

Status field progression:

| Mode | Progression |
|---|---|
| Sandbox | `queued` → `scanning` → `executing` → `complete` |
| Signature | `queued` → `scanning` → `analyzing` → `complete` |

**List recent jobs**

```http
GET /api/jobs
```

Returns up to 50 jobs summarised (filename, mode, status, AV verdict, risk level/score or signature hit count).

**Delete a job**

```http
DELETE /api/jobs/<job_id>
```

Removes the job record, uploaded file, patched binary, and YARA file.

**Download patched binary** *(signature mode)*

```http
GET /api/jobs/<job_id>/patched
```

**Download YARA rules** *(signature mode)*

```http
GET /api/jobs/<job_id>/yara
```

---

## Result structure

### Sandbox job

```json
{
  "job_id": "...",
  "filename": "sample.exe",
  "mode": "sandbox",
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
    "sysmon_alerts": [],
    "timeline": [],
    "risk_score": {
      "score": 42,
      "level": "medium",
      "reasons": ["Spawned 1 new process(es)", "Suspicious child processes: cmd.exe"]
    }
  }
}
```

### Signature job

```json
{
  "job_id": "...",
  "filename": "payload.exe",
  "mode": "signature",
  "status": "complete",
  "scan_result": {
    "verdict": "threat_detected",
    "threats": ["Trojan:Win32/Mimikatz.E"],
    "hashes": { "md5": "...", "sha1": "...", "sha256": "..." }
  },
  "signature_result": {
    "engine_version": "4.18.0.0",
    "signature_version": "1.409.0.0",
    "hits": [
      {
        "index": 0,
        "offset": 4096,
        "offset_hex": "0x1000",
        "signature": "Trojan:Win32/Mimikatz.E",
        "pe_section": ".text",
        "entropy": 6.2341,
        "entropy_note": "medium -- mixed content",
        "strings": ["MiniDump", "sekurlsa"],
        "load_bearing_offsets": [4090, 4091, 4095],
        "flagged_bytes_hex": "DE AD BE EF ...",
        "yara_rule": "rule DefenderCheck_Hit_0 { ... }"
      }
    ],
    "patched_file": "C:\\MalwareAnalysis\\uploads\\<id>_payload_patched.exe",
    "clean_after_patching": true
  }
}
```

---

## Concurrent submissions

The server accepts multiple simultaneous uploads, but running more than one sample at a time causes monitoring cross-contamination (process and network events bleed between sandbox jobs). Add a serialisation semaphore in `app.py`:

```python
# Near the top of app.py, after imports
_analysis_lock = threading.Semaphore(1)

# Wrap run_analysis() with:
def run_analysis(job_id, filepath, duration, mode, no_sensitivity):
    jobs[job_id]["status"] = "queued"
    jobs[job_id]["phase"]  = "Waiting for previous analysis to finish..."
    _persist_job(job_id)

    with _analysis_lock:
        # ... existing function body ...
```

This is less critical for signature analysis since it does not execute samples, but it still prevents two binary searches from competing for disk I/O in `tmp\`.

---

## Running the unit tests

The `defender_check` package ships with 226 unit tests. All Defender interactions are mocked, so tests run on any platform including Linux and macOS.

```powershell
pip install -r requirements-dev.txt
python -m pytest tests\ -v
```

---

## Operational security

> This sandbox is a **detection and triage tool**, not a hardened containment environment. Treat every analysis session as potentially contaminating the VM.

- **Snapshot before, restore after.** Take a clean VirtualBox snapshot before any analysis session. Restore it after — do not reuse a VM that has executed malware.
- **Network isolation.** Use a host-only or isolated NAT adapter. The VM needs no internet access after initial setup. Network protection is disabled inside the VM (so malware connections are observable); the hypervisor network adapter is the containment boundary.
- **Elevated execution.** Samples run with the same privileges as the server process (the Scheduled Task runs elevated). Assume kernel-level compromise is possible; restore the snapshot regardless of apparent behaviour.
- **Excluded paths.** `uploads\`, `results\`, and `tmp\` are excluded from Defender's real-time scanning. Do not add other paths to this list.
- **Signature mode is safer.** The binary search never executes the sample. It is safe to run signature analysis on highly suspicious files where you would not want to execute them at all.
- **Logs.** Server output is written to `C:\MalwareAnalysis\logs\server.log`. Result JSON files persist in `results\` across reboots but are wiped on snapshot restore.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `setup.ps1` parse error | Non-ASCII characters in the script (encoding issue) | Re-download the zip; `setup.ps1` is pure ASCII and must not be re-saved by Notepad |
| `WinDefend service is not running` | Defender disabled | Re-enable Windows Defender and re-run `setup.ps1` |
| `MpCmdRun.exe not found` | Non-standard install path or post-update relocation | `defender_check\scanner.py` searches the registry, the static path, and the platform-versioned directory under `ProgramData`; re-enable Defender if fully disabled |
| Signature analysis returns all clean | Real-time protection quarantined the temp slices | Verify `tmp\` is in the Defender exclusion list: `Get-MpPreference \| Select-Object -ExpandProperty ExclusionPath` |
| Signature analysis very slow | Sensitivity analysis running on a large file | Check *Skip sensitivity analysis* in the UI, or pass `no_sensitivity=true` via the API |
| Scan returns `return_code -2147023895` | File locked by another process | Wait a moment and resubmit |
| No processes appear in sandbox results | Process auditing not enabled | Re-run `setup.ps1` or run `auditpol /set /subcategory:"Process Creation" /success:enable` |
| Sysmon events missing | Sysmon not installed | Run `setup.ps1` (installs Sysmon automatically), or install manually with `-i localscan.xml` |
| Server not reachable from host | Firewall rule missing | Re-run `setup.ps1`, or add an inbound TCP 5000 rule manually |
| `pip install` fails | No internet or proxy required | Download wheels manually: `pip install --no-index --find-links=. -r requirements.txt` |

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| [Flask](https://flask.palletsprojects.com/) | >= 3.0 | HTTP API and template serving |
| [psutil](https://github.com/giampaolo/psutil) | >= 5.9 | Process and network connection snapshots (sandbox mode) |
| [pywin32](https://github.com/mhammond/pywin32) | >= 306 | Windows event log access via `wevtutil` wrapper |
| [pefile](https://github.com/erocarrera/pefile) | >= 2023.2.7 | PE section mapping for signature hits |
| [tqdm](https://github.com/tqdm/tqdm) | >= 4.64.0 | Progress bars during binary search and sensitivity analysis |

All installed automatically by `setup.ps1`.
