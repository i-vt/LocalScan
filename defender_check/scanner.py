"""
scanner.py — all interaction with Windows Defender.

Responsibilities
----------------
- Locate MpCmdRun.exe (registry → static path → platform-versioned directory)
- Read engine / signature version from the registry
- Invoke MpCmdRun.exe and parse its exit code + stdout

The active MpCmdRun.exe path is stored in a module-level variable and
set once at startup via configure().  This avoids threading it through
every call-site while still making it explicit and testable.
"""

import os
import re
import subprocess
import sys
from typing import Optional

from .models import ScanResult

# ── Optional Windows registry access ─────────────────────────────────────────
try:
    import winreg
    _HAS_WINREG = True
except ImportError:
    _HAS_WINREG = False

# ── Module-level config ───────────────────────────────────────────────────────
_DEFAULT_MPCMDRUN = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
# Defender platform updates move the binary here; subdirs are version strings.
_PLATFORM_DIR     = r"C:\ProgramData\Microsoft\Windows Defender\Platform"
_SCAN_TIMEOUT     = 30   # seconds before a single MpCmdRun call is abandoned
_MAX_RETRIES      = 3    # retry attempts on timeout

_mpcmdrun: str = ""      # set by configure() before any scan() call


def configure(path: str) -> None:
    """Store the resolved MpCmdRun.exe path for use by scan()."""
    global _mpcmdrun
    _mpcmdrun = path


# ── Discovery ─────────────────────────────────────────────────────────────────
def locate_mpcmdrun() -> str:
    """
    Return the path to MpCmdRun.exe.

    Search order:
      1. Registry InstallLocation key (handles non-default installs / Server).
      2. Well-known static path (C:\\Program Files\\Windows Defender\\).
      3. Platform-versioned directory (C:\\ProgramData\\Microsoft\\Windows
         Defender\\Platform\\<version>\\) — the binary moves here after
         Defender platform updates.

    Raises FileNotFoundError if none of the three locations yield a file.
    """
    # 1 — Registry
    if _HAS_WINREG:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Defender",
            )
            install_dir = winreg.QueryValueEx(key, "InstallLocation")[0]
            winreg.CloseKey(key)
            candidate = os.path.join(install_dir, "MpCmdRun.exe")
            if os.path.isfile(candidate):
                return candidate
        except OSError:
            pass

    # 2 — Static default path
    if os.path.isfile(_DEFAULT_MPCMDRUN):
        return _DEFAULT_MPCMDRUN

    # 3 — Platform-versioned directory (newest version first)
    if os.path.isdir(_PLATFORM_DIR):
        for version in sorted(os.listdir(_PLATFORM_DIR), reverse=True):
            candidate = os.path.join(_PLATFORM_DIR, version, "MpCmdRun.exe")
            if os.path.isfile(candidate):
                return candidate

    raise FileNotFoundError(
        "MpCmdRun.exe not found. Is Windows Defender installed?\n"
        f"Tried: {_DEFAULT_MPCMDRUN}\n"
        f"Also searched: {_PLATFORM_DIR}"
    )


def get_defender_info() -> tuple[str, str]:
    """
    Return (engine_version, signature_version) from the Windows registry.
    Returns ("unknown", "unknown") on non-Windows or if the key is missing.
    """
    if not _HAS_WINREG:
        return "unknown", "unknown"
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Signature Updates",
        )
        engine = winreg.QueryValueEx(key, "EngineVersion")[0]
        sigs   = winreg.QueryValueEx(key, "SignatureVersion")[0]
        winreg.CloseKey(key)
        return engine, sigs
    except OSError:
        return "unknown", "unknown"


# ── Scanning ──────────────────────────────────────────────────────────────────
def scan(filepath: str, get_sig: bool = False) -> tuple[str, Optional[str]]:
    """
    Invoke MpCmdRun.exe on *filepath* and return (ScanResult constant, sig_name).

    Uses subprocess.run with capture_output=True to avoid the stdout-pipe
    deadlock risk that plagued the original C# implementation.
    Retries up to _MAX_RETRIES times on timeout before giving up.
    """
    if not os.path.isfile(filepath):
        return ScanResult.NOT_FOUND, None

    proc = None
    for attempt in range(_MAX_RETRIES):
        try:
            proc = subprocess.run(
                [
                    _mpcmdrun,
                    "-Scan", "-ScanType", "3",
                    "-File", filepath,
                    "-DisableRemediation",
                    "-Trace", "-Level", "0x10",
                ],
                capture_output=True,
                text=True,
                timeout=_SCAN_TIMEOUT,
            )
            break
        except subprocess.TimeoutExpired:
            if attempt == _MAX_RETRIES - 1:
                return ScanResult.TIMEOUT, None
        except FileNotFoundError:
            print(f"[-] MpCmdRun.exe not found: {_mpcmdrun}", file=sys.stderr)
            sys.exit(1)

    if proc is None:
        return ScanResult.ERROR, None

    sig_name = None
    if get_sig and proc.stdout:
        m = re.search(r"Threat\s*:\s*(\S+)", proc.stdout, re.IGNORECASE)
        if m:
            sig_name = m.group(1)

    if proc.returncode == 0:
        return ScanResult.NO_THREAT, sig_name
    if proc.returncode == 2:
        return ScanResult.THREAT, sig_name
    return ScanResult.ERROR, sig_name
