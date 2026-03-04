"""Parallel Bandit adapter — multi-process Python security detection.

This module implements true parallelization for Bandit security scanning by:
1. Dividing files into weighted batches (by file size for load balancing)
2. Launching worker processes that run Bandit on file subsets
3. Streaming results from workers via temporary JSON files
4. Aggregating findings as workers complete

Architecture:
    Main Process (Coordinator)
        ↓ spawns
    Worker Pool (N processes)
        ↓ each runs
    bandit file1.py file2.py ... -f json --quiet
        ↓ writes to
    {tempdir}/worker_{id}_{uuid}.json
        ↓ signals completion via
    Result Queue
        ↓ main process reads
    Aggregated Findings

Performance characteristics:
- O(n/workers) time complexity vs O(n) single-process
- Optimal for codebases with 200+ files
- Adaptive: falls back to single-process for small codebases
- Resilient: worker crashes don't halt entire scan
"""

from __future__ import annotations

import concurrent.futures
import orjson
import logging
import multiprocessing
import os
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from desloppify.core._internal.text_utils import PROJECT_ROOT
from desloppify.engine.policy.zones import FileZoneMap, Zone

from .bandit_adapter import (
    BanditRunStatus,
    BanditScanResult,
    _to_security_entry,
)

logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_WORKER_COUNT = max(2, multiprocessing.cpu_count() - 1)
MIN_FILES_FOR_PARALLEL = 50  # Below this, single-process is faster
TARGET_FILES_PER_BATCH = 25  # Target batch size (adjusted by file size weighting)
WORKER_TIMEOUT_SECONDS = 120  # Per-worker timeout
BATCH_SIZE_BYTES_TARGET = 500_000  # ~500KB target per batch for load balancing
MAX_RETRY_ATTEMPTS = 3  # Maximum retry attempts per batch (1 initial + 2 retries)


@dataclass(frozen=True)
class WorkerBatch:
    """File batch allocated to a worker process."""

    files: tuple[str, ...]
    batch_id: int
    total_size_bytes: int


@dataclass(frozen=True)
class WorkerResult:
    """Result from a completed worker process."""

    batch_id: int
    files_scanned: int
    output_path: Path | None
    status: str  # 'ok', 'timeout', 'error', 'parse_error'
    detail: str = ""
    attempt: int = 1  # Which attempt this result is from (1 = first attempt)


def _get_file_size_safe(filepath: str) -> int:
    """Get file size in bytes, return 0 on error."""
    try:
        return os.path.getsize(filepath)
    except OSError:
        return 0


def _should_scan_file(filepath: str, zone_map: FileZoneMap | None) -> bool:
    """Check if file should be scanned based on zone policy.
    
    Excludes GENERATED and VENDOR zones to avoid wasting Bandit on generated code.
    """
    if zone_map is None:
        return True
    zone = zone_map.get(filepath)
    return zone not in (Zone.GENERATED, Zone.VENDOR)


def weighted_batch_splitter(
    files: list[str],
    zone_map: FileZoneMap | None,
    num_workers: int,
) -> list[WorkerBatch]:
    """Split files into batches weighted by file size for load balancing.
    
    Strategy:
    1. Filter out GENERATED/VENDOR zones (don't scan at all)
    2. Sort files by size (largest first)
    3. Use greedy bin-packing: assign each file to least-loaded worker
    4. Result: batches with approximately equal total byte size
    
    Args:
        files: All Python files discovered
        zone_map: Zone classification map for filtering
        num_workers: Target number of batches (one per worker)
        
    Returns:
        List of WorkerBatch instances, one per worker
    """
    # Filter files by zone policy
    filtered_files = [f for f in files if _should_scan_file(f, zone_map)]
    
    if not filtered_files:
        return []
    
    # Get file sizes for weighting
    file_sizes = [(f, _get_file_size_safe(f)) for f in filtered_files]
    
    # Sort by size descending (largest first for better bin-packing)
    file_sizes.sort(key=lambda x: x[1], reverse=True)
    
    # Initialize workers with empty batches
    worker_batches: list[list[tuple[str, int]]] = [[] for _ in range(num_workers)]
    worker_totals = [0] * num_workers
    
    # Greedy bin-packing: assign each file to least-loaded worker
    for filepath, size in file_sizes:
        # Find worker with minimum current load
        min_worker_idx = min(range(num_workers), key=lambda i: worker_totals[i])
        worker_batches[min_worker_idx].append((filepath, size))
        worker_totals[min_worker_idx] += size
    
    # Convert to WorkerBatch instances (filter out empty batches)
    batches = []
    for batch_id, batch in enumerate(worker_batches):
        if batch:
            files_only = tuple(f for f, _ in batch)
            total_size = sum(s for _, s in batch)
            batches.append(
                WorkerBatch(
                    files=files_only,
                    batch_id=batch_id,
                    total_size_bytes=total_size,
                )
            )
    
    logger.debug(
        "Split %d files into %d batches (avg: %.1f files, %.1f KB per batch)",
        len(filtered_files),
        len(batches),
        len(filtered_files) / len(batches) if batches else 0,
        sum(b.total_size_bytes for b in batches) / len(batches) / 1024 if batches else 0,
    )
    
    return batches


def _bandit_worker_process(
    batch: WorkerBatch,
    temp_dir: Path,
    timeout: int,
) -> WorkerResult:
    """Worker process that runs Bandit on a file batch.
    
    This function runs in a separate process. It:
    1. Runs `bandit file1.py file2.py ... -f json --quiet`
    2. Writes JSON output to temp file
    3. Returns WorkerResult with status
    
    Args:
        batch: Files to scan in this worker
        temp_dir: Temporary directory for output files
        timeout: Subprocess timeout in seconds
        
    Returns:
        WorkerResult indicating success/failure and output location
    """
    worker_id = os.getpid()
    output_filename = f"worker_{batch.batch_id}_{uuid.uuid4().hex[:8]}.json"
    output_path = temp_dir / output_filename
    
    logger.debug(
        "Worker %d (batch %d): scanning %d files (%.1f KB)",
        worker_id,
        batch.batch_id,
        len(batch.files),
        batch.total_size_bytes / 1024,
    )
    
    # Build Bandit command: scan specific files (not recursive)
    cmd = [
        "bandit",
        "-f", "json",
        "--quiet",
        *batch.files,  # Pass files directly to Bandit
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "Worker %d (batch %d): timeout after %ds",
            worker_id,
            batch.batch_id,
            timeout,
        )
        return WorkerResult(
            batch_id=batch.batch_id,
            files_scanned=0,
            output_path=None,
            status="timeout",
            detail=f"timeout={timeout}s",
        )
    except OSError as exc:
        logger.warning(
            "Worker %d (batch %d): OSError: %s",
            worker_id,
            batch.batch_id,
            exc,
        )
        return WorkerResult(
            batch_id=batch.batch_id,
            files_scanned=0,
            output_path=None,
            status="error",
            detail=str(exc),
        )
    
    stdout = result.stdout.strip()
    if not stdout:
        # Bandit exits 0 with no output when there's nothing to report
        return WorkerResult(
            batch_id=batch.batch_id,
            files_scanned=len(batch.files),
            output_path=None,
            status="ok",
        )
    
    # Validate JSON before writing to temp file
    try:
        orjson.loads(stdout)
    except orjson.JSONDecodeError as exc:
        logger.warning(
            "Worker %d (batch %d): JSON parse error: %s",
            worker_id,
            batch.batch_id,
            exc,
        )
        return WorkerResult(
            batch_id=batch.batch_id,
            files_scanned=0,
            output_path=None,
            status="parse_error",
            detail=str(exc),
        )
    
    # Write validated JSON to temp file
    try:
        output_path.write_text(stdout, encoding="utf-8")
    except OSError as exc:
        logger.warning(
            "Worker %d (batch %d): failed to write output: %s",
            worker_id,
            batch.batch_id,
            exc,
        )
        return WorkerResult(
            batch_id=batch.batch_id,
            files_scanned=0,
            output_path=None,
            status="error",
            detail=f"write_error: {exc}",
        )
    
    logger.debug(
        "Worker %d (batch %d): completed, wrote %s",
        worker_id,
        batch.batch_id,
        output_path.name,
    )
    
    return WorkerResult(
        batch_id=batch.batch_id,
        files_scanned=len(batch.files),
        output_path=output_path,
        status="ok",
    )


def _aggregate_worker_results(
    worker_results: list[WorkerResult],
    zone_map: FileZoneMap | None,
) -> tuple[list[dict], int, BanditRunStatus]:
    """Aggregate findings from all completed workers.
    
    Reads JSON output files, converts to security entries, and merges results.
    
    Args:
        worker_results: Results from all workers (completed + failed)
        zone_map: Zone map for filtering individual findings
        
    Returns:
        Tuple of (entries, files_scanned, overall_status)
    """
    entries: list[dict] = []
    total_files_scanned = 0
    failed_batches = 0
    timeout_batches = 0
    
    for worker_result in worker_results:
        total_files_scanned += worker_result.files_scanned
        
        if worker_result.status == "timeout":
            timeout_batches += 1
            continue
        elif worker_result.status != "ok":
            failed_batches += 1
            continue
        
        # Read and parse worker output file
        if worker_result.output_path and worker_result.output_path.exists():
            try:
                data = orjson.loads(worker_result.output_path.read_text(encoding="utf-8"))
                raw_results: list[dict] = data.get("results", [])
                
                for res in raw_results:
                    entry = _to_security_entry(res, zone_map)
                    if entry is not None:
                        entries.append(entry)
                        
            except (orjson.JSONDecodeError, OSError) as exc:
                logger.warning(
                    "Failed to read worker output %s: %s",
                    worker_result.output_path,
                    exc,
                )
                failed_batches += 1
    
    # Determine overall status
    if timeout_batches > 0:
        status = BanditRunStatus(
            state="timeout",
            detail=f"{timeout_batches} of {len(worker_results)} batches timed out",
        )
    elif failed_batches == len(worker_results):
        status = BanditRunStatus(
            state="error",
            detail=f"all {failed_batches} batches failed",
        )
    elif failed_batches > 0:
        status = BanditRunStatus(
            state="ok",
            detail=f"{failed_batches} of {len(worker_results)} batches failed (partial results)",
        )
    else:
        status = BanditRunStatus(state="ok")
    
    logger.debug(
        "Aggregated %d findings from %d files (%d batches, %d failed, %d timeout)",
        len(entries),
        total_files_scanned,
        len(worker_results),
        failed_batches,
        timeout_batches,
    )
    
    return entries, total_files_scanned, status


def detect_with_bandit_parallel(
    files: list[str],
    zone_map: FileZoneMap | None,
    *,
    workers: int | None = None,
    timeout: int = WORKER_TIMEOUT_SECONDS,
) -> BanditScanResult:
    """Run Bandit security checks in parallel using multiprocessing.
    
    This is the main entry point for parallel Bandit scanning. It:
    1. Splits files into weighted batches
    2. Spawns worker pool to scan batches in parallel
    3. Collects and aggregates results from workers
    4. Returns unified BanditScanResult
    
    Args:
        files: List of Python file paths to scan
        zone_map: Zone classification for filtering
        workers: Number of worker processes (None = auto-detect)
        timeout: Per-worker timeout in seconds
        
    Returns:
        BanditScanResult with aggregated findings from all workers
    """
    if workers is None:
        workers = DEFAULT_WORKER_COUNT
    
    # Create temp directory for worker output files
    temp_dir = Path(tempfile.mkdtemp(prefix="bandit_parallel_"))
    
    try:
        # Split files into batches using weighted allocation
        batches = weighted_batch_splitter(files, zone_map, workers)
        
        if not batches:
            logger.debug("No files to scan after zone filtering")
            return BanditScanResult(
                entries=[],
                files_scanned=0,
                status=BanditRunStatus(state="ok"),
            )
        
        # Adjust worker count to actual batch count (may be less than requested)
        actual_workers = len(batches)
        
        logger.debug(
            "Starting parallel Bandit scan: %d workers, %d batches, timeout=%ds",
            actual_workers,
            len(batches),
            timeout,
        )
        
        # Launch worker pool and process batches with retry logic
        start_time = time.time()
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=actual_workers) as executor:
            # Track batches and their retry attempts
            batch_attempts: dict[int, int] = {batch.batch_id: 1 for batch in batches}
            batches_to_process = list(batches)
            all_results: list[WorkerResult] = []
            
            while batches_to_process:
                # Submit current batch set asynchronously
                futures = {
                    executor.submit(_bandit_worker_process, batch, temp_dir, timeout): batch
                    for batch in batches_to_process
                }
                
                # Collect results and identify failures
                current_results: list[WorkerResult] = []
                failed_batches: list[WorkerBatch] = []

                def _record_failure(batch: WorkerBatch, status: str, detail: str) -> None:
                    attempt = batch_attempts[batch.batch_id]
                    current_results.append(
                        WorkerResult(
                            batch_id=batch.batch_id,
                            files_scanned=0,
                            output_path=None,
                            status=status,
                            detail=detail,
                            attempt=attempt,
                        )
                    )
                    if attempt < MAX_RETRY_ATTEMPTS:
                        logger.warning(
                            "Batch %d failed (attempt %d/%d): %s - %s. Retrying...",
                            batch.batch_id,
                            attempt,
                            MAX_RETRY_ATTEMPTS,
                            status,
                            detail,
                        )
                        failed_batches.append(batch)
                        batch_attempts[batch.batch_id] = attempt + 1
                    else:
                        logger.error(
                            "Batch %d failed all %d attempts: %s - %s",
                            batch.batch_id,
                            MAX_RETRY_ATTEMPTS,
                            status,
                            detail,
                        )

                processed_futures: set[concurrent.futures.Future[WorkerResult]] = set()
                try:
                    for future in concurrent.futures.as_completed(futures, timeout=timeout + 30):
                        processed_futures.add(future)
                        batch = futures[future]
                        try:
                            # Wait for worker with generous timeout (worker has its own timeout)
                            result = future.result()
                            if result.status == "ok":
                                current_results.append(
                                    WorkerResult(
                                        batch_id=result.batch_id,
                                        files_scanned=result.files_scanned,
                                        output_path=result.output_path,
                                        status=result.status,
                                        detail=result.detail,
                                        attempt=batch_attempts[batch.batch_id],
                                    )
                                )
                            else:
                                _record_failure(batch, result.status, result.detail)

                        except Exception as exc:
                            _record_failure(batch, "error", str(exc))
                except concurrent.futures.TimeoutError:
                    logger.warning(
                        "Bandit worker pool timeout: unfinished batches will be retried or marked failed"
                    )

                # Handle futures not yielded by as_completed() before timeout.
                for future, batch in futures.items():
                    if future in processed_futures:
                        continue

                    if future.done():
                        try:
                            result = future.result()
                            if result.status == "ok":
                                current_results.append(
                                    WorkerResult(
                                        batch_id=result.batch_id,
                                        files_scanned=result.files_scanned,
                                        output_path=result.output_path,
                                        status=result.status,
                                        detail=result.detail,
                                        attempt=batch_attempts[batch.batch_id],
                                    )
                                )
                            else:
                                _record_failure(batch, result.status, result.detail)
                        except Exception as exc:
                            _record_failure(batch, "error", str(exc))
                        continue

                    future.cancel()
                    _record_failure(batch, "timeout", "pool timeout waiting for completion")
                
                all_results.extend(current_results)
                batches_to_process = failed_batches
                
                if batches_to_process:
                    logger.debug(
                        "Retrying %d failed batches...",
                        len(batches_to_process),
                    )
        
        elapsed = time.time() - start_time
        logger.debug("Parallel Bandit scan completed in %.2fs", elapsed)
        
        # Check if any batch failed all retry attempts
        permanently_failed = [
            r for r in all_results
            if r.status != "ok" and r.attempt >= MAX_RETRY_ATTEMPTS
        ]
        
        if permanently_failed:
            # Return empty results if any batch failed all attempts
            failed_batch_ids = [r.batch_id for r in permanently_failed]
            error_details = [
                f"batch {r.batch_id}: {r.status} - {r.detail}"
                for r in permanently_failed
            ]
            logger.error(
                "Parallel Bandit scan failed: %d batches failed all %d attempts. "
                "Returning empty results. Failed batches: %s",
                len(permanently_failed),
                MAX_RETRY_ATTEMPTS,
                ", ".join(error_details),
            )
            return BanditScanResult(
                entries=[],
                files_scanned=0,
                status=BanditRunStatus(
                    state="error",
                    detail=f"{len(permanently_failed)} batch(es) failed all retry attempts: {', '.join(error_details)}",
                ),
            )
        
        # Aggregate findings from all workers (all succeeded or were retried successfully)
        entries, files_scanned, status = _aggregate_worker_results(
            all_results,
            zone_map,
        )
        
        return BanditScanResult(
            entries=entries,
            files_scanned=files_scanned,
            status=status,
        )
        
    finally:
        # Clean up temp directory
        try:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception as exc:
            logger.debug("Failed to clean temp dir %s: %s", temp_dir, exc)


def should_use_parallel_bandit(file_count: int) -> bool:
    """Determine if parallel Bandit is beneficial for given file count.
    
    Heuristic: parallel overhead not worth it for small codebases.
    
    Checks DESLOPPIFY_PARALLEL first, then DESLOPPIFY_BANDIT_PARALLEL for
    backward compatibility, then auto-detects based on file count.
    
    Args:
        file_count: Number of files to scan
        
    Returns:
        True if parallel mode should be used, False otherwise
    """
    from desloppify.engine.parallel_utils import should_parallelize
    
    return should_parallelize(
        file_count,
        min_files=MIN_FILES_FOR_PARALLEL,
        legacy_env_var="DESLOPPIFY_BANDIT_PARALLEL"
    )


__all__ = [
    "detect_with_bandit_parallel",
    "should_use_parallel_bandit",
    "weighted_batch_splitter",
    "WorkerBatch",
    "WorkerResult",
]
