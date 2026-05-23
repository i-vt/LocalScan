"""
monitor.py - Dynamic execution monitoring
Executes a sample, watches for N seconds, then kills it.
Monitors: new processes, network connections, Defender events, Sysmon events.
"""

import subprocess
import os
import time
import threading
from datetime import datetime
from typing import Optional

import psutil


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

def snapshot_processes() -> dict:
    """Return {pid: info_dict} for all live processes."""
    procs = {}
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid", "create_time"]):
        try:
            procs[p.pid] = p.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return procs


def snapshot_connections() -> set:
    """Return a set of 'laddr->raddr' strings for active connections."""
    seen = set()
    try:
        for c in psutil.net_connections(kind="all"):
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            seen.add(f"{laddr}->{raddr}")
    except Exception:
        pass
    return seen


def snapshot_connections_full() -> list:
    """Return full connection info list."""
    result = []
    try:
        for c in psutil.net_connections(kind="all"):
            try:
                result.append({
                    "laddr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "status": c.status,
                    "pid":    c.pid,
                })
            except Exception:
                pass
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Event log helpers (wevtutil – no external dep needed)
# ---------------------------------------------------------------------------

def _wevtutil_count(logname: str) -> int:
    """Return current number of records in a log, or 0 on failure."""
    try:
        r = subprocess.run(
            ["wevtutil", "gi", logname],
            capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.splitlines():
            if "numberOfLogRecords" in line:
                return int(line.split(":")[-1].strip())
    except Exception:
        pass
    return 0


def _wevtutil_query(logname: str, max_events: int = 30, query: str = "") -> list:
    """Query an event log, return list of text-formatted events."""
    events = []
    try:
        cmd = ["wevtutil", "qe", logname, f"/c:{max_events}", "/rd:true", "/f:text"]
        if query:
            cmd += [f"/q:{query}"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        # Split on blank-line-separated blocks
        blocks = r.stdout.strip().split("\n\n")
        for b in blocks:
            if b.strip():
                parsed = {}
                for line in b.splitlines():
                    line = line.strip()
                    if ":" in line:
                        k, _, v = line.partition(":")
                        parsed[k.strip()] = v.strip()
                if parsed:
                    events.append(parsed)
    except Exception:
        pass
    return events


def get_defender_events(max_events: int = 30) -> list:
    return _wevtutil_query(
        "Microsoft-Windows-Windows Defender/Operational",
        max_events=max_events,
    )


def get_sysmon_events(max_events: int = 50) -> list:
    """Read Sysmon Operational log if available."""
    return _wevtutil_query(
        "Microsoft-Windows-Sysmon/Operational",
        max_events=max_events,
    )


def sysmon_available() -> bool:
    try:
        r = subprocess.run(
            ["wevtutil", "gl", "Microsoft-Windows-Sysmon/Operational"],
            capture_output=True, text=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

def kill_process_tree(pid: int):
    """Kill a process and all its descendants."""
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except Exception:
                pass
        try:
            parent.kill()
        except Exception:
            pass
    except psutil.NoSuchProcess:
        pass


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

SUSPICIOUS_PROCS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "wmic.exe", "msiexec.exe",
    "schtasks.exe", "reg.exe", "net.exe", "netsh.exe",
    "at.exe", "sc.exe", "bcdedit.exe",
}


def calculate_risk(result: dict) -> dict:
    score = 0
    reasons = []

    if result.get("defender_alerts"):
        score += 60
        reasons.append(f"Windows Defender fired {len(result['defender_alerts'])} alert(s)")

    if result.get("sysmon_alerts"):
        score += 20
        reasons.append(f"Sysmon logged {len(result['sysmon_alerts'])} event(s) during execution")

    new_procs = result.get("new_processes", [])
    if new_procs:
        score += min(len(new_procs) * 4, 15)
        reasons.append(f"Spawned {len(new_procs)} new process(es)")

    susp = [p for p in new_procs if p.get("name", "").lower() in SUSPICIOUS_PROCS]
    if susp:
        score += len(susp) * 8
        names = ", ".join({p["name"] for p in susp})
        reasons.append(f"Suspicious child processes: {names}")

    new_conns = result.get("new_connections", [])
    if new_conns:
        score += min(len(new_conns) * 8, 25)
        reasons.append(f"Opened {len(new_conns)} network connection(s)")

    score = min(score, 100)
    if score == 0:
        level = "clean"
    elif score < 25:
        level = "low"
    elif score < 55:
        level = "medium"
    elif score < 80:
        level = "high"
    else:
        level = "critical"

    return {"score": score, "level": level, "reasons": reasons}


# ---------------------------------------------------------------------------
# Main monitor entry point
# ---------------------------------------------------------------------------

def execute_and_monitor(filepath: str, duration: int) -> dict:
    """
    Execute the sample and monitor for `duration` seconds.
    Returns a structured dict of all findings.
    """
    result = {
        "timestamp":          datetime.now().isoformat(),
        "filepath":           filepath,
        "duration_requested": duration,
        "actual_duration":    0.0,
        "sample_pid":         None,
        "exit_code":          None,
        "terminated_by_us":   False,
        "timeline":           [],
        "new_processes":      [],
        "new_connections":    [],
        "defender_alerts":    [],
        "sysmon_alerts":      [],
        "sysmon_available":   False,
        "errors":             [],
        "risk_score":         {},
    }

    def log(etype: str, data: str):
        result["timeline"].append({
            "time": round(time.time() - start_time, 2),
            "type": etype,
            "data": data,
        })

    # ---- pre-execution baseline ----
    pre_procs   = snapshot_processes()
    pre_conns   = snapshot_connections()
    pre_def_cnt = _wevtutil_count("Microsoft-Windows-Windows Defender/Operational")

    _sysmon = sysmon_available()
    result["sysmon_available"] = _sysmon
    pre_sys_cnt = _wevtutil_count("Microsoft-Windows-Sysmon/Operational") if _sysmon else 0

    # ---- launch sample ----
    try:
        proc = subprocess.Popen(
            [filepath],
            cwd=os.path.dirname(filepath) or ".",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        result["sample_pid"] = proc.pid
    except Exception as e:
        result["errors"].append(f"Execution failed: {e}")
        result["risk_score"] = calculate_risk(result)
        return result

    start_time = time.time()
    log("execution_start", f"Process started – PID {proc.pid}")

    seen_pids  = set(pre_procs.keys())
    seen_conns = set(pre_conns)
    last_event_check = 0.0

    # ---- monitoring loop ----
    try:
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time

            # Check if the sample already exited
            if proc.poll() is not None:
                result["exit_code"] = proc.returncode
                log("process_exit", f"Sample exited with code {proc.returncode} at {elapsed:.1f}s")
                break

            # -- new processes (poll every 0.5 s) --
            current_procs = snapshot_processes()
            for pid, info in current_procs.items():
                if pid not in seen_pids:
                    seen_pids.add(pid)
                    cmdline = " ".join(info.get("cmdline") or [])[:200]
                    entry = {
                        "pid":     pid,
                        "name":    info.get("name", ""),
                        "exe":     info.get("exe", ""),
                        "cmdline": cmdline,
                        "ppid":    info.get("ppid"),
                        "time":    round(elapsed, 2),
                    }
                    result["new_processes"].append(entry)
                    log("new_process",
                        f"PID {pid} [{info.get('name','')}] – {cmdline[:120]}")

            # -- new network connections --
            current_conns_full = snapshot_connections_full()
            for c in current_conns_full:
                key = f"{c['laddr']}->{c['raddr']}"
                if key not in seen_conns and c["raddr"]:
                    seen_conns.add(key)
                    c["time"] = round(elapsed, 2)
                    result["new_connections"].append(c)
                    log("network",
                        f"{c['laddr']} → {c['raddr']}  [{c['status']}]  PID {c['pid']}")

            # -- event log checks (every 2 s) --
            if elapsed - last_event_check >= 2.0:
                last_event_check = elapsed

                cur_def = _wevtutil_count(
                    "Microsoft-Windows-Windows Defender/Operational"
                )
                if cur_def > pre_def_cnt:
                    new_evs = get_defender_events(max_events=cur_def - pre_def_cnt + 5)
                    for ev in new_evs:
                        result["defender_alerts"].append(ev)
                        log("defender_alert", str(ev)[:300])
                    pre_def_cnt = cur_def

                if _sysmon:
                    cur_sys = _wevtutil_count("Microsoft-Windows-Sysmon/Operational")
                    if cur_sys > pre_sys_cnt:
                        new_sys = get_sysmon_events(
                            max_events=cur_sys - pre_sys_cnt + 10
                        )
                        for ev in new_sys:
                            result["sysmon_alerts"].append(ev)
                        pre_sys_cnt = cur_sys

            time.sleep(0.5)

    except Exception as e:
        result["errors"].append(f"Monitor loop error: {e}")

    finally:
        # Kill whatever is still running
        if proc.poll() is None:
            kill_process_tree(result["sample_pid"])
            result["terminated_by_us"] = True
            log("terminated", f"Sample killed after {round(time.time()-start_time,1)}s")

        result["actual_duration"] = round(time.time() - start_time, 2)

    # Final event log flush
    cur_def = _wevtutil_count("Microsoft-Windows-Windows Defender/Operational")
    if cur_def > pre_def_cnt:
        for ev in get_defender_events(max_events=cur_def - pre_def_cnt + 5):
            if ev not in result["defender_alerts"]:
                result["defender_alerts"].append(ev)
                log("defender_alert_final", str(ev)[:300])

    result["risk_score"] = calculate_risk(result)
    return result
