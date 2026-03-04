"""Cross-language security detector entrypoint."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from desloppify.base.discovery.file_paths import resolve_scan_file
from desloppify.engine.policy.zones import FileZoneMap

from .filters import _is_test_file, _should_scan_file, _should_skip_line
from .scanner import _scan_line_for_security_entries

logger = logging.getLogger(__name__)


def scan_single_file(
    filepath: str,
    zone_map: FileZoneMap | None,
    scan_root: Path,
) -> tuple[list[dict[str, Any]], bool]:
    """Scan a single file for security issues.
    
    Note: Assumes file has already been filtered by zone (caller's responsibility).
    
    Args:
        filepath: Path to file to scan
        zone_map: Zone classification map (for test file detection only)
        scan_root: Root directory for path resolution
        
    Returns:
        Tuple of (entries, was_scanned) where:
            - entries: List of security issue dictionaries
            - was_scanned: Boolean indicating if file was actually scanned
    """
    entries: list[dict[str, Any]] = []
    
    is_test = _is_test_file(filepath, zone_map)
    resolved_path = resolve_scan_file(filepath, scan_root=scan_root)
    
    if resolved_path is None or not resolved_path.exists():
        return entries, False
    
    try:
        with open(resolved_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                # Skip comments unless they contain secrets
                if _should_skip_line(line):
                    continue
                    
                line_entries = _scan_line_for_security_entries(
                    filepath=filepath,
                    line_num=line_num,
                    line=line,
                    is_test=is_test,
                )
                entries.extend(line_entries)
    except (OSError, UnicodeDecodeError) as e:
        logger.debug("Failed to scan %s: %s", filepath, e)
        return entries, False
    
    return entries, True


def scan_file_batch(
    files: list[str],
    zone_map: FileZoneMap | None,
    scan_root: Path,
) -> tuple[list[dict[str, Any]], int]:
    """Scan a batch of files for security issues (worker function for parallel execution).
    
    This function is designed to be called by multiprocessing workers. It processes
    a batch of files and returns aggregated results.
    
    Args:
        files: List of file paths to scan in this batch
        zone_map: Zone classification map (can be full map or batch-specific subset)
        scan_root: Root directory for path resolution
        
    Returns:
        Tuple of (entries, scanned_count) where:
            - entries: List of all security issue dictionaries from all files
            - scanned_count: Number of files that were actually scanned
    """
    all_entries: list[dict[str, Any]] = []
    scanned_count = 0
    
    for filepath in files:
        entries, was_scanned = scan_single_file(filepath, zone_map, scan_root)
        all_entries.extend(entries)
        if was_scanned:
            scanned_count += 1
    
    return all_entries, scanned_count


def _scan_batch_worker_wrapper(
    files: list[str], zone_map: FileZoneMap | None, scan_root: Path, **kwargs
) -> dict[str, Any]:
    """Wrapper for scan_file_batch that returns a dict for easier aggregation.
    
    This wrapper converts the tuple return value into a dict to work better
    with process_files_parallel's aggregation modes.
    
    Returns:
        Dict with keys 'entries' (list) and 'scanned' (int)
    """
    entries, scanned = scan_file_batch(files, zone_map, scan_root)
    return {"entries": entries, "scanned": scanned}


def detect_security_issues(
    files: list[str],
    zone_map: FileZoneMap | None,
    lang_name: str,
    *,
    scan_root: Path | None = None,
    parallel: bool | None = None,
    workers: int | None = None,
) -> tuple[list[dict], int]:
    """Detect cross-language security issues.
    
    Uses universal parallel framework for automatic parallel/sequential selection.
    
    Args:
        files: List of file paths to scan
        zone_map: Zone classification map for filtering
        lang_name: (Unused, kept for API compatibility)
        scan_root: Root directory for path resolution
        parallel: True=force parallel, False=force sequential, None=auto
        workers: (Unused, framework calculates internally)
        
    Returns:
        Tuple of (entries, files_scanned)
    """
    _ = lang_name
    _ = workers
    
    resolved_scan_root = scan_root.resolve() if isinstance(scan_root, Path) else Path.cwd()
    filtered_files = [f for f in files if _should_scan_file(f, zone_map)]
    
    if not filtered_files:
        return [], 0
    
    # Optimization: skip framework overhead for forced sequential mode
    if parallel is False:
        return scan_file_batch(filtered_files, zone_map, resolved_scan_root)
    
    # Use framework with retry support and fail-safe behavior
    # Note: Using extend mode with wrapper that returns dicts
    batch_results = process_files_parallel(
        files=filtered_files,
        worker_func=_scan_batch_worker_wrapper,
        mode="extend",  # Get list of result dicts
        max_retries=MAX_RETRY_ATTEMPTS,
        fail_on_incomplete=True,
        timeout=BATCH_TIMEOUT_SECONDS,
        task_name="SecurityScan",
        min_files=100,
        force_parallel=parallel,
        zone_map=zone_map,
        scan_root=resolved_scan_root,
    )
    
    # Handle both sequential (single dict) and parallel (list of dicts) results
    # Sequential mode returns dict directly, parallel returns list of dicts
    if isinstance(batch_results, dict):
        # Sequential mode - single batch result
        return batch_results["entries"], batch_results["scanned"]
    
    # Parallel mode - aggregate multiple batch results
    all_entries: list[dict] = []
    total_scanned = 0
    for result in batch_results:
        all_entries.extend(result["entries"])
        total_scanned += result["scanned"]
    
    return all_entries, total_scanned
