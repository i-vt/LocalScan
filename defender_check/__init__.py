"""
DefenderCheck — full-featured Windows Defender signature analyser.

Features
--------
  Multi-signature detection  — finds every flagged region in one run
  Auto-patching              — writes a zeroed copy with all hits removed
  Byte sensitivity analysis  — pinpoints exact load-bearing bytes per hit
  PE section mapping         — correlates offsets with .text / .rdata / etc.
  String extraction          — ASCII + UTF-16LE from each flagged region
  Entropy analysis           — helps classify what the signature keys on
  Defender version info      — engine + sig version pulled from the registry
  Progress bars              — requires tqdm   (pip install tqdm)
  JSON output                — --json emits a machine-readable report
  Registry-based discovery   — locates MpCmdRun.exe without a hardcoded path
  YARA rule sketches         — wildcards at non-load-bearing byte positions

Requirements (Windows only)
---------------------------
    pip install pefile tqdm

Usage — CLI
-----------
    python -m defender_check <binary> [--debug] [--no-sensitivity] [--json]

Usage — library
---------------
    from defender_check import analyse
    from defender_check.scanner import configure, locate_mpcmdrun

    configure(locate_mpcmdrun())
    report = analyse("payload.exe")
    for hit in report.hits:
        print(hit.offset_hex, hit.signature)
"""

from .analysis import calc_entropy, entropy_note, extract_strings, hex_dump, pe_section_at
from .cli import main
from .models import Hit, Report, ScanResult
from .orchestrator import analyse
from .scanner import configure, get_defender_info, locate_mpcmdrun, scan
from .search import binary_search, sensitivity_analysis
from .yara_gen import generate_yara

__all__ = [
    # Models
    "Hit",
    "Report",
    "ScanResult",
    # Scanner
    "configure",
    "locate_mpcmdrun",
    "get_defender_info",
    "scan",
    # Analysis
    "calc_entropy",
    "entropy_note",
    "extract_strings",
    "pe_section_at",
    "hex_dump",
    # Search
    "binary_search",
    "sensitivity_analysis",
    # YARA
    "generate_yara",
    # Pipeline
    "analyse",
    # CLI
    "main",
]
