"""Bandit adapter — Python security detection via the bandit static analyser.

Runs ``bandit -r -f json --quiet <path>`` as a subprocess and converts its JSON
output into the security entry dicts expected by ``phase_security``.

Bandit covers AST-level security checks (shell injection, unsafe deserialization,
SQL injection, etc.) more reliably than custom regex/AST patterns. When bandit is
installed, it is used as the lang-specific security detector; otherwise
Python-specific security checks will be skipped.

Bandit severity → desloppify tier/confidence mapping:
  HIGH   → tier=4, confidence="high"
  MEDIUM → tier=3, confidence="medium"
  LOW    → tier=3, confidence="low"

The ``check_id`` in the entry detail is the bandit test ID (e.g., "B602") so
issues are stable across reruns and can be wontfix-tracked by ID.
"""

from __future__ import annotations

import orjson
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from desloppify.base.discovery.file_paths import rel
from desloppify.base.discovery.paths import get_project_root
from desloppify.engine.policy.zones import FileZoneMap, Zone
from desloppify.languages._framework.base.types import DetectorCoverageStatus

logger = logging.getLogger(__name__)

# Import bandit_parallel lazily to avoid circular import
# (bandit_parallel imports from this module)
if TYPE_CHECKING:
    from . import bandit_parallel

_SEVERITY_TO_TIER = {"HIGH": 4, "MEDIUM": 3, "LOW": 3}
_SEVERITY_TO_CONFIDENCE = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

# Bandit test IDs that overlap with the cross-language security detector
# (secret names, hardcoded passwords). Skip these to avoid duplicate issues.
_CROSS_LANG_OVERLAP = frozenset(
    {
        "B105",  # hardcoded_password_string
        "B106",  # hardcoded_password_funcarg
        "B107",  # hardcoded_password_default
        "B501",  # request_with_no_cert_validation  (covered by weak_crypto_tls)
        "B502",  # ssl_with_bad_version
        "B503",  # ssl_with_bad_defaults
        "B504",  # ssl_with_no_version
        "B505",  # weak_cryptographic_key
    }
)

_BANDIT_IMPACT_TEXT = (
    "Python-specific security checks were skipped; this can miss shell injection, "
    "unsafe deserialization, and risky SQL/subprocess patterns."
)


BanditRunState = Literal["ok", "missing_tool", "timeout", "error", "parse_error"]


@dataclass(frozen=True)
class BanditRunStatus:
    """Typed execution status for a Bandit adapter invocation."""

    state: BanditRunState
    detail: str = ""
    tool: str = "bandit"

    def coverage(self) -> DetectorCoverageStatus | None:
        """Convert non-success statuses into detector coverage metadata."""
        if self.state == "ok":
            return None

        if self.state == "missing_tool":
            return DetectorCoverageStatus(
                detector="security",
                status="reduced",
                confidence=0.6,
                summary="bandit is not installed — Python-specific security checks were skipped.",
                impact=_BANDIT_IMPACT_TEXT,
                remediation="Install Bandit: pip install bandit",
                tool=self.tool,
                reason="missing_dependency",
            )

        if self.state == "timeout":
            return DetectorCoverageStatus(
                detector="security",
                status="reduced",
                confidence=0.75,
                summary="bandit timed out — Python-specific security checks were skipped this scan.",
                impact=_BANDIT_IMPACT_TEXT,
                remediation="Rerun scan or run `bandit -r -f json --quiet <path>` manually.",
                tool=self.tool,
                reason="timeout",
            )

        if self.state == "parse_error":
            return DetectorCoverageStatus(
                detector="security",
                status="reduced",
                confidence=0.75,
                summary="bandit output could not be parsed — Python-specific security checks were skipped this scan.",
                impact=_BANDIT_IMPACT_TEXT,
                remediation="Update/reinstall Bandit and rerun scan.",
                tool=self.tool,
                reason="parse_error",
            )

        return DetectorCoverageStatus(
            detector="security",
            status="reduced",
            confidence=0.75,
            summary="bandit failed to execute — Python-specific security checks were skipped this scan.",
            impact=_BANDIT_IMPACT_TEXT,
            remediation="Verify Bandit is runnable and rerun scan.",
            tool=self.tool,
            reason="execution_error",
        )


@dataclass(frozen=True)
class BanditScanResult:
    """Bandit issues plus typed execution status."""

    entries: list[dict]
    files_scanned: int
    status: BanditRunStatus


def _to_security_entry(
    result: dict,
    zone_map: FileZoneMap | None,
) -> dict | None:
    """Convert a single bandit result dict to a security entry, or None to skip."""
    filepath = str(result.get("filename", "") or "")
    if not filepath:
        return None

    rel_path = rel(filepath)

    # Apply zone filtering — only GENERATED and VENDOR are excluded for security.
    if zone_map is not None:
        zone = zone_map.get(rel_path)
        if zone in (Zone.TEST, Zone.CONFIG, Zone.GENERATED, Zone.VENDOR):
            return None

    test_id = result.get("test_id", "")
    if test_id in _CROSS_LANG_OVERLAP:
        return None

    raw_severity = result.get("issue_severity", "MEDIUM").upper()
    raw_confidence = result.get("issue_confidence", "MEDIUM").upper()

    # Suppress LOW-severity + LOW-confidence (very noisy, low signal).
    if raw_severity == "LOW" and raw_confidence == "LOW":
        return None

    tier = _SEVERITY_TO_TIER.get(raw_severity, 3)
    confidence = _SEVERITY_TO_CONFIDENCE.get(raw_severity, "medium")

    line = result.get("line_number", 0)
    summary = result.get("issue_text", "")
    test_name = result.get("test_name", test_id)
    return {
        "file": rel_path,
        "name": f"security::{test_id}::{rel_path}::{line}",
        "tier": tier,
        "confidence": confidence,
        "summary": f"[{test_id}] {summary}",
        "detail": {
            "kind": test_id,
            "severity": raw_severity.lower(),
            "line": line,
            "content": result.get("code", "")[:200],
            "remediation": result.get("more_info", ""),
            "test_name": test_name,
            "source": "bandit",
        },
    }


def _detect_with_bandit_single(
    path: Path,
    zone_map: FileZoneMap | None,
    timeout: int = 120,
    exclude_dirs: list[str] | None = None,
) -> BanditScanResult:
    """Run bandit on *path* and return issues + typed execution status.

    Parameters
    ----------
    path:
        Directory to scan recursively
    zone_map:
        Zone classification map for filtering findings
    timeout:
        Subprocess timeout in seconds
    exclude_dirs:
        Absolute directory paths to pass to bandit's ``--exclude`` flag.
        When non-empty, bandit will skip these directories during its
        recursive scan.
        
    Returns
    -------
    BanditScanResult with findings and execution status
    """
    cmd = [
        "bandit",
        "-r",
        "-f",
        "json",
        "--quiet",
    ]
    if exclude_dirs:
        cmd.extend(["--exclude", ",".join(exclude_dirs)])
    cmd.append(str(path.resolve()))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=get_project_root(),
            timeout=timeout,
        )
    except FileNotFoundError:
        logger.debug("bandit: not installed — Python-specific security checks will be skipped")
        return BanditScanResult(
            entries=[],
            files_scanned=0,
            status=BanditRunStatus(state="missing_tool"),
        )
    except subprocess.TimeoutExpired:
        logger.debug("bandit: timed out after %ds", timeout)
        return BanditScanResult(
            entries=[],
            files_scanned=0,
            status=BanditRunStatus(state="timeout", detail=f"timeout={timeout}s"),
        )
    except OSError as exc:
        logger.debug("bandit: OSError: %s", exc)
        return BanditScanResult(
            entries=[],
            files_scanned=0,
            status=BanditRunStatus(state="error", detail=str(exc)),
        )

    stdout = result.stdout.strip()
    if not stdout:
        # Bandit exits 0 with no output when there's nothing to scan.
        return BanditScanResult(
            entries=[],
            files_scanned=0,
            status=BanditRunStatus(state="ok"),
        )

    try:
        data = orjson.loads(stdout)
    except orjson.JSONDecodeError as exc:
        logger.debug("bandit: JSON parse error: %s", exc)
        return BanditScanResult(
            entries=[],
            files_scanned=0,
            status=BanditRunStatus(state="parse_error", detail=str(exc)),
        )

    raw_results: list[dict] = data.get("results", [])
    metrics: dict = data.get("metrics", {})

    # Count scanned files from metrics (bandit reports per-file stats).
    files_scanned = sum(
        1
        for key in metrics
        if key != "_totals" and not key.endswith("_totals")
    )

    entries: list[dict] = []
    for res in raw_results:
        entry = _to_security_entry(res, zone_map)
        if entry is not None:
            entries.append(entry)

    logger.debug("bandit: %d issues from %d files", len(entries), files_scanned)
    return BanditScanResult(
        entries=entries,
        files_scanned=files_scanned,
        status=BanditRunStatus(state="ok"),
    )


def _detect_with_bandit_files_single(
    files: list[str],
    zone_map: FileZoneMap | None,
    timeout: int = 120,
) -> BanditScanResult:
    """Run bandit in single-process mode on specific files.
    
    This runs `bandit file1.py file2.py ...` directly without recursive directory scanning.
    Used for file-list mode when parallel execution is not beneficial (< 50 files).

    Parameters
    ----------
    files:
        List of Python file paths to scan
    zone_map:
        Zone classification map for filtering findings
    timeout:
        Subprocess timeout in seconds
        
    Returns
    -------
    BanditScanResult with findings and execution status
    """
    # Filter files by zone before scanning (exclude GENERATED/VENDOR)
    def _should_scan_file(filepath: str) -> bool:
        if zone_map is None:
            return True
        zone = zone_map.get(filepath)
        return zone not in (Zone.GENERATED, Zone.VENDOR)
    
    filtered_files = [f for f in files if _should_scan_file(f)]
    
    if not filtered_files:
        logger.debug("bandit: no files to scan after zone filtering")
        return BanditScanResult(
            entries=[],
            files_scanned=0,
            status=BanditRunStatus(state="ok"),
        )
    
    # Build command: bandit on specific files (not recursive)
    cmd = [
        "bandit",
        "-f",
        "json",
        "--quiet",
        *filtered_files,  # Pass files directly to Bandit
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            timeout=timeout,
        )
    except FileNotFoundError:
        logger.debug("bandit: not installed — Python-specific security checks will be skipped")
        return BanditScanResult(
            entries=[],
            files_scanned=0,
            status=BanditRunStatus(state="missing_tool"),
        )
    except subprocess.TimeoutExpired:
        logger.debug("bandit: timed out after %ds", timeout)
        return BanditScanResult(
            entries=[],
            files_scanned=0,
            status=BanditRunStatus(state="timeout", detail=f"timeout={timeout}s"),
        )
    except OSError as exc:
        logger.debug("bandit: OSError: %s", exc)
        return BanditScanResult(
            entries=[],
            files_scanned=0,
            status=BanditRunStatus(state="error", detail=str(exc)),
        )
    
    stdout = result.stdout.strip()
    if not stdout:
        # Bandit exits 0 with no output when there's nothing to report
        return BanditScanResult(
            entries=[],
            files_scanned=len(filtered_files),
            status=BanditRunStatus(state="ok"),
        )
    
    try:
        data = orjson.loads(stdout)
    except orjson.JSONDecodeError as exc:
        logger.debug("bandit: JSON parse error: %s", exc)
        return BanditScanResult(
            entries=[],
            files_scanned=0,
            status=BanditRunStatus(state="parse_error", detail=str(exc)),
        )
    
    raw_results: list[dict] = data.get("results", [])
    metrics: dict = data.get("metrics", {})
    
    # Count scanned files from metrics (bandit reports per-file stats)
    files_scanned = sum(
        1
        for key in metrics
        if key != "_totals" and not key.endswith("_totals")
    )
    
    # Fallback: if no metrics, use filtered file count
    if files_scanned == 0:
        files_scanned = len(filtered_files)
    
    entries: list[dict] = []
    for res in raw_results:
        entry = _to_security_entry(res, zone_map)
        if entry is not None:
            entries.append(entry)
    
    logger.debug("bandit: %d findings from %d files", len(entries), files_scanned)
    return BanditScanResult(
        entries=entries,
        files_scanned=files_scanned,
        status=BanditRunStatus(state="ok"),
    )


def detect_with_bandit(
    path: Path | None = None,
    zone_map: FileZoneMap | None = None,
    timeout: int = 120,
    exclude_dirs: list[str] | None = None,
    *,
    files: list[str] | None = None,
    parallel: bool | None = None,
) -> BanditScanResult:
    """Run Bandit security checks with adaptive single/parallel mode selection.
    
    This is the main entry point for Bandit scanning. It automatically selects
    between single-process and parallel modes based on file count and configuration.
    
    Modes:
    - **Directory mode** (path provided): Scans directory recursively
    - **File-list mode** (files provided): Scans specific files, enables parallelization
    
    Parallelization:
    - Auto-enabled for 50+ files (configurable via DESLOPPIFY_BANDIT_PARALLEL env var)
    - Falls back to single-process if multiprocessing unavailable
    - Force enable: parallel=True or DESLOPPIFY_BANDIT_PARALLEL=true
    - Force disable: parallel=False or DESLOPPIFY_BANDIT_PARALLEL=false
    
    Parameters
    ----------
    path:
        Directory to scan recursively (directory mode)
    zone_map:
        Zone classification map for filtering findings
    timeout:
        Per-worker timeout in seconds (parallel mode) or total timeout (single mode)
    exclude_dirs:
        Directory exclusions (only used in single-process directory mode)
    files:
        Specific files to scan (file-list mode, enables parallelization)
    parallel:
        Force parallel mode on/off (None = auto-detect based on file count)
        
    Returns
    -------
    BanditScanResult with findings and execution status
    
    Examples
    --------
    Directory mode (single-process):
    >>> detect_with_bandit(Path("/project"), zone_map, exclude_dirs=[".venv"])
    
    File-list mode (adaptive parallelization):
    >>> detect_with_bandit(files=python_files, zone_map=zone_map)
    
    Force parallel mode:
    >>> detect_with_bandit(files=python_files, zone_map=zone_map, parallel=True)
    """
    # File-list mode: can use parallel implementation
    if files is not None:
        # Lazy import to avoid circular dependency
        bandit_parallel = None
        try:
            from . import bandit_parallel
        except ImportError as e:
            logger.debug("bandit_parallel import failed: %s", e)
        
        # Determine if parallel mode should be used
        use_parallel = parallel
        if use_parallel is None:
            # Auto-detect: use parallel for 50+ files
            use_parallel = (
                bandit_parallel is not None
                and bandit_parallel.should_use_parallel_bandit(len(files))
            )
        elif use_parallel and bandit_parallel is None:
            logger.warning(
                "Parallel mode requested but not available (import failed), "
                "falling back to single-process"
            )
            use_parallel = False
        
        if use_parallel and bandit_parallel is not None:
            logger.debug(
                "Using parallel Bandit mode for %d files",
                len(files),
            )
            return bandit_parallel.detect_with_bandit_parallel(
                files=files,
                zone_map=zone_map,
                timeout=timeout,
            )
        else:
            # File-list mode with single process: run bandit on files directly
            logger.debug(
                "Using single-process Bandit mode for %d files (below threshold)",
                len(files),
            )
            return _detect_with_bandit_files_single(
                files=files,
                zone_map=zone_map,
                timeout=timeout,
            )
    
    # Directory mode: use single-process recursive scan
    if path is None:
        raise ValueError(
            "Either 'path' (directory mode) or 'files' (file-list mode) must be provided"
        )
    
    logger.debug("Using single-process directory mode for %s", path)
    return _detect_with_bandit_single(
        path=path,
        zone_map=zone_map,
        timeout=timeout,
        exclude_dirs=exclude_dirs,
    )
