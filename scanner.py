"""
scanner.py - Windows Defender static scan integration
Calls MpCmdRun.exe, parses output, returns structured verdict.
"""

import subprocess
import os
import hashlib
import re
from datetime import datetime

DEFENDER_PATHS = [
    r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    r"C:\ProgramData\Microsoft\Windows Defender\Platform",  # fallback – we'll search
]


def find_mpcmdrun() -> str | None:
    """Locate MpCmdRun.exe – the path moves with platform updates."""
    static = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
    if os.path.exists(static):
        return static

    # Search the platform directory for the newest version
    platform_dir = r"C:\ProgramData\Microsoft\Windows Defender\Platform"
    if os.path.isdir(platform_dir):
        versions = sorted(os.listdir(platform_dir), reverse=True)
        for v in versions:
            candidate = os.path.join(platform_dir, v, "MpCmdRun.exe")
            if os.path.exists(candidate):
                return candidate

    return None


def get_file_hashes(filepath: str) -> dict:
    hashes = {}
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        hashes["md5"]    = hashlib.md5(data).hexdigest()
        hashes["sha1"]   = hashlib.sha1(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()
    except Exception as e:
        hashes["error"] = str(e)
    return hashes


def get_file_magic(filepath: str) -> str:
    """Read first 8 bytes and return a hex magic string."""
    try:
        with open(filepath, "rb") as f:
            return f.read(8).hex().upper()
    except Exception:
        return "unknown"


def scan_with_defender(filepath: str) -> dict:
    """
    Run a targeted scan with Windows Defender.
    Returns a structured dict with verdict, threat names, hashes, etc.
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
        result["error"]   = "MpCmdRun.exe not found – is Windows Defender installed?"
        return result

    try:
        # -DisableRemediation prevents Defender from quarantining during scan
        proc = subprocess.run(
            [mpcmd, "-Scan", "-ScanType", "3", "-File", filepath, "-DisableRemediation"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        result["raw_output"]  = output.strip()
        result["return_code"] = proc.returncode

        # Return code semantics:
        #   0 = clean / no threat found
        #   2 = threat found
        #  -2147023895 (0x80070019) = access denied / file locked
        if proc.returncode == 2:
            result["verdict"] = "threat_detected"
            # Try to extract threat name from output
            matches = re.findall(r"(?i)threat(?:\s+name)?\s*[:\-]\s*(.+)", output)
            if matches:
                result["threats"] = [m.strip() for m in matches]
            else:
                # Fallback: any line mentioning a threat keyword
                for line in output.splitlines():
                    if any(k in line.lower() for k in ["trojan", "virus", "malware",
                                                        "ransom", "exploit", "worm",
                                                        "backdoor", "adware", "spyware"]):
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
