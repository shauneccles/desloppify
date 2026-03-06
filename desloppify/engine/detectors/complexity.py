"""Complexity signal detection: configurable per-language complexity signals."""

import inspect
import logging
import re
from pathlib import Path

from desloppify.base.output.fallbacks import log_best_effort_failure
from desloppify.base.discovery.file_paths import resolve_scan_file
from desloppify.engine.parallel_utils import process_files_parallel

logger = logging.getLogger(__name__)


def _process_file_for_complexity(
    filepath: str, path: Path, signals, threshold: int, min_loc: int
) -> dict | None:
    """Process a single file for complexity signals.
    
    Args:
        filepath: File path to analyze
        path: Root scan path for path resolution
        signals: List of ComplexitySignal objects
        threshold: Minimum score to flag a file
        min_loc: Minimum LOC to consider
        
    Returns:
        Dict with complexity entry or None if below threshold
    """
    try:
        p = resolve_scan_file(filepath, scan_root=path)
        content = p.read_text()
        lines = content.splitlines()
        loc = len(lines)
        if loc < min_loc:
            return None

        file_signals = []
        score = 0

        for sig in signals:
            try:
                if sig.compute:
                    # Pass filepath to compute fns that accept it (tree-sitter signals).
                    accepts_filepath = "_filepath" in inspect.signature(
                        sig.compute
                    ).parameters
                    if accepts_filepath:
                        result = sig.compute(content, lines, _filepath=filepath)
                    else:
                        result = sig.compute(content, lines)
                    if result:
                        count, label = result
                        file_signals.append(label)
                        excess = (
                            max(0, count - sig.threshold) if sig.threshold else count
                        )
                        score += excess * sig.weight
                elif sig.pattern:
                    count = len(re.findall(sig.pattern, content, re.MULTILINE))
                    if count > sig.threshold:
                        file_signals.append(f"{count} {sig.name}")
                        score += (count - sig.threshold) * sig.weight
            except (TypeError, ValueError, KeyError, AttributeError, re.error) as exc:
                log_best_effort_failure(
                    logger,
                    f"compute complexity signal '{sig.name}' for {filepath}",
                    exc,
                )
                continue

        if file_signals and score >= threshold:
            return {
                "file": filepath,
                "loc": loc,
                "score": score,
                "signals": file_signals,
            }
        return None
    except (OSError, UnicodeDecodeError) as exc:
        log_best_effort_failure(
            logger,
            f"read complexity detector candidate {filepath}",
            exc,
        )
        return None


def _complexity_worker(
    files: list[str], path: Path, signals, threshold: int, min_loc: int
) -> list[dict]:
    """Worker function for parallel complexity detection.
    
    Processes a batch of files and returns complexity entries.
    
    Args:
        files: Batch of file paths to process
        path: Root scan path
        signals: List of ComplexitySignal objects
        threshold: Minimum score to flag
        min_loc: Minimum LOC to consider
        
    Returns:
        List of complexity entries
    """
    entries = []
    for filepath in files:
        entry = _process_file_for_complexity(filepath, path, signals, threshold, min_loc)
        if entry:
            entries.append(entry)
    return entries


def detect_complexity(
    path: Path, signals, file_finder, threshold: int = 15, min_loc: int = 50
) -> tuple[list[dict], int]:
    """Detect files with complexity signals."""
    files = file_finder(path)
    
    # Use parallel processing for large file sets
    entries = process_files_parallel(
        files=files,
        worker_func=_complexity_worker,
        mode="extend",
        min_files=50,  # Parallel overhead worthwhile for 50+ files
        task_name="complexity detection",
        path=path,
        signals=signals,
        threshold=threshold,
        min_loc=min_loc
    )
    
    return sorted(entries, key=lambda e: -e["score"]), len(files)
