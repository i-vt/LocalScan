"""
scanner.py — Windows Defender static scan integration.

Provides scan_with_defender(), which runs a targeted MpCmdRun.exe scan
and returns a structured verdict dict (hashes, threats, raw output, etc.).

MpCmdRun.exe discovery is delegated to defender_check.scanner.locate_mpcmdrun()
so both the sandbox and signature-analysis modes use identical discovery logic
(registry → static path → platform-versioned directory).
"""

import hashlib
import os
import re
import subprocess
from datetime import datetime

from defender_check.scanner import locate_mpcmdrun as _locate_mpcmdrun


# ── MpCmdRun discovery ────────────────────────────────────────────────────────

def find_mpcmdrun() -> str | None:
    """
    Return the path to MpCmdRun.exe, or None if not found.

    Wraps defender_check.scanner.locate_mpcmdrun() so both analysis modes
    share the same search order: registry → static path → platform directory.
    """
    try:
        return _locate_mpcmdrun()
    except FileNotFoundError:
        return None


# ── File metadata ─────────────────────────────────────────────────────────────

def get_file_hashes(filepath: str) -> dict:
    hashes = {}
    try:
        with open(filepath, "rb") as fh:
            data = fh.read()
        hashes["md5"]    = hashlib.md5(data).hexdigest()
        hashes["sha1"]   = hashlib.sha1(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        hashes["error"] = str(e)
    return hashes


def get_file_magic(filepath: str) -> str:
    """Read first 8 bytes and return a hex magic string."""
    try:
        with open(filepath, "rb") as fh:
            return fh.read(8).hex().upper()
    except Exception:
        return "unknown"


# ── Static scan ───────────────────────────────────────────────────────────────

def scan_with_defender(filepath: str) -> dict:
    """
    Run a targeted Windows Defender scan on *filepath*.

    Returns a structured dict with:
      verdict     — "clean" | "threat_detected" | "scan_error" | "scan_timeout" | "error"
      threats     — list of threat name strings (if any)
      hashes      — md5 / sha1 / sha256
      filesize    — bytes
      magic       — first 8 bytes as uppercase hex
      raw_output  — full MpCmdRun.exe stdout+stderr
      return_code — MpCmdRun exit code (0 = clean, 2 = threat)
      error       — human-readable error string, or None
    """
    result = {
        "timestamp":   datetime.now().isoformat(),
        "filepath":    filepath,
        "filename":    os.path.basename(filepath),
        "filesize":    0,
        "magic":       "",
        "hashes":      {},
        "verdict":     "unknown",
        "threats":     [],
        "raw_output":  "",
        "return_code": None,
        "error":       None,
    }

    try:
        result["filesize"] = os.path.getsize(filepath)
        result["magic"]    = get_file_magic(filepath)
        result["hashes"]   = get_file_hashes(filepath)
    except Exception as e:
        result["error"] = f"File read error: {e}"
        return result

    mpcmd = find_mpcmdrun()
    if not mpcmd:
        result["verdict"] = "error"
        result["error"]   = "MpCmdRun.exe not found — is Windows Defender installed?"
        return result

    try:
        # -DisableRemediation prevents Defender from quarantining during the scan
        # so we can still execute the sample in sandbox mode.
        proc = subprocess.run(
            [mpcmd, "-Scan", "-ScanType", "3", "-File", filepath, "-DisableRemediation"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        result["raw_output"]  = output.strip()
        result["return_code"] = proc.returncode

        if proc.returncode == 2:
            result["verdict"] = "threat_detected"
            # Primary: look for an explicit "Threat name: …" line
            matches = re.findall(r"(?i)threat(?:\s+name)?\s*[:\-]\s*(.+)", output)
            if matches:
                result["threats"] = [m.strip() for m in matches]
            else:
                # Fallback: scan lines for known malware keywords
                for line in output.splitlines():
                    if any(k in line.lower() for k in [
                        "trojan", "virus", "malware", "ransom", "exploit",
                        "worm", "backdoor", "adware", "spyware",
                    ]):
                        result["threats"].append(line.strip())
                if not result["threats"]:
                    result["threats"] = ["Unknown threat (Defender return code 2)"]

        elif proc.returncode == 0:
            result["verdict"] = "clean"
        else:
            result["verdict"] = "scan_error"
            result["error"]   = f"MpCmdRun exited with code {proc.returncode}"

    except subprocess.TimeoutExpired:
        result["verdict"] = "scan_timeout"
        result["error"]   = "Scan timed out after 120 seconds"
    except Exception as e:
        result["verdict"] = "scan_error"
        result["error"]   = str(e)

    return result
