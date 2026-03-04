"""Large file detection (LOC threshold)."""

import logging
from pathlib import Path

from desloppify.base.output.fallbacks import log_best_effort_failure
from desloppify.base.discovery.file_paths import count_lines, resolve_scan_file

logger = logging.getLogger(__name__)


def _process_large_file(filepath: str, path: Path, threshold: int) -> dict | None:
    """Process a single file to check if it exceeds the LOC threshold."""
    try:
        p = resolve_scan_file(filepath, scan_root=path)
        loc = len(p.read_text().splitlines())
        if loc > threshold:
            return {"file": filepath, "loc": loc}
    except (OSError, UnicodeDecodeError) as exc:
        log_best_effort_failure(
            logger,
            f"read large-file detector candidate {filepath}",
            exc,
        )
    return None


def _large_file_worker(files: list[str], path: Path, threshold: int) -> list[dict]:
    """Worker function to process a batch of files for large file detection."""
    entries = []
    for filepath in files:
        entry = _process_large_file(filepath, path, threshold)
        if entry is not None:
            entries.append(entry)
    return entries


def detect_large_files(
    path: Path, file_finder, threshold: int = 500
) -> tuple[list[dict], int]:
    """Find files exceeding a line count threshold."""
    files = file_finder(path)
    entries = []
    for filepath in files:
        try:
            p = resolve_scan_file(filepath, scan_root=path)
            loc = count_lines(p)
            if loc > threshold:
                entries.append({"file": filepath, "loc": loc})
        except (OSError, UnicodeDecodeError) as exc:
            log_best_effort_failure(
                logger,
                f"read large-file detector candidate {filepath}",
                exc,
            )
            continue
    return sorted(entries, key=lambda e: -e["loc"]), len(files)
