"""Universal parallel execution framework for file processing.

This module provides a truly modular system for parallelizing ANY file-based loop
across the entire codebase. Uses concurrent.futures.ProcessPoolExecutor for Windows
compatibility.

Key Features:
    - Universal API: Works with any `for filepath in files` loop
    - Flexible aggregation: Supports list extend, count accumulation, dict merging
    - Auto-detection: Intelligently decides when parallelization is worthwhile
    - Type-safe: Generic typing for result aggregation
    - Composable: Easy to add custom processing logic

Environment Variables:
    DESLOPPIFY_PARALLEL: Global control for ALL multiprocessing (true/false/1/0/yes/no)
        - 'true', '1', 'yes': Force enable parallel execution
        - 'false', '0', 'no': Force disable parallel execution
        - Unset or other: Auto-detect based on file count

Example Usage:
    ```python
    # Sequential (old way)
    entries = []
    for filepath in files:
        result = process_file(filepath)
        entries.extend(result)
    
    # Parallel (new way)
    from desloppify.engine._parallel_utils import process_files_parallel
    
    entries = process_files_parallel(
        files=files,
        worker_func=process_file,
        mode="extend",  # or "count", "dict_merge"
    )
    ```
"""

from __future__ import annotations

import concurrent.futures
import logging
import multiprocessing
import os
import pickle
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Callable, Any, TypeVar, Literal, TYPE_CHECKING, Generic

if TYPE_CHECKING:
    from desloppify.engine.policy.zones import FileZoneMap

logger = logging.getLogger(__name__)

T = TypeVar("T")
ResultType = TypeVar("ResultType")


# =============================================================================
# Core Configuration
# =============================================================================

DEFAULT_MIN_FILES = 50  # Minimum files to justify parallel overhead
DEFAULT_BATCH_SIZE = 10  # Minimum files per worker
BATCH_TIMEOUT_SECONDS = 180  # 3-minute timeout per batch
MAX_RETRY_ATTEMPTS = 3  # Maximum retries for failed batches


# Scan-lifetime persistent pool (optional, enabled by caller context)
_PERSISTENT_POOL: ContextVar[concurrent.futures.ProcessPoolExecutor | None] = ContextVar(
    "desloppify_parallel_persistent_pool",
    default=None,
)


@contextmanager
def persistent_parallel_pool(max_workers: int | None = None):
    """Create/reuse a process pool for the lifetime of a higher-level workflow.

    When active, ``process_files_parallel`` reuses this executor instead of
    creating a new ``ProcessPoolExecutor`` for each detector phase.
    """
    existing = _PERSISTENT_POOL.get()
    if existing is not None:
        yield existing
        return

    worker_count = max_workers or max(1, get_cpu_count() - 1)
    executor = concurrent.futures.ProcessPoolExecutor(max_workers=worker_count)
    token = _PERSISTENT_POOL.set(executor)
    logger.debug("Started persistent parallel pool (%d workers)", worker_count)
    try:
        yield executor
    finally:
        _PERSISTENT_POOL.reset(token)
        executor.shutdown(wait=True)
        logger.debug("Stopped persistent parallel pool")


# =============================================================================
# CPU & Environment Detection
# =============================================================================

def get_cpu_count() -> int:
    """Get number of available CPU cores, accounting for containerization."""
    cpu_count = os.cpu_count() or 1
    
    #Check for Docker/container CPU limits
    try:
        with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") as f:
            quota = int(f.read().strip())
        with open("/sys/fs/cgroup/cpu/cpu.cfs_period_us") as f:
            period = int(f.read().strip())
        if quota > 0 and period > 0:
            container_cpus = max(1, quota // period)
            return min(cpu_count, container_cpus)
    except (FileNotFoundError, ValueError, PermissionError):
        pass
    
    return cpu_count


def check_parallel_override() -> bool | None:
    """Check global DESLOPPIFY_PARALLEL environment variable.
    
    Returns:
        True if parallel is explicitly enabled
        False if parallel is explicitly disabled
        None if auto-detection should be used
    """
    env_val = os.getenv("DESLOPPIFY_PARALLEL", "").lower()
    if env_val in ("true", "1", "yes"):
        return True
    elif env_val in ("false", "0", "no"):
        return False
    return None


def should_parallelize(
    file_count: int, 
    min_files: int = DEFAULT_MIN_FILES,
    legacy_env_var: str | None = None
) -> bool:
    """Determine if parallelization is worthwhile.
    
    Checks DESLOPPIFY_PARALLEL first, falls back to legacy env var, then auto-detects.
    
    Args:
        file_count: Number of files to process
        min_files: Minimum files needed to justify parallel overhead
        legacy_env_var: Optional legacy environment variable name (for backward compat)
        
    Returns:
        True if should use parallel execution
    """
    # Check global override first
    global_override = check_parallel_override()
    if global_override is not None:
        return global_override
    
    # Check legacy variable for backward compatibility
    if legacy_env_var:
        env_val = os.getenv(legacy_env_var, "").lower()
        if env_val in ("true", "1", "yes"):
            return True
        if env_val in ("false", "0", "no"):
            return False
    
    # Auto-detect based on file count
    return file_count >= min_files


def calculate_workers(
    file_count: int,
    min_batch_size: int = DEFAULT_BATCH_SIZE,
    max_workers: int | None = None
) -> int:
    """Calculate optimal number of worker processes.
    
    Args:
        file_count: Total number of files to process
        min_batch_size: Minimum files per worker to avoid overhead
        max_workers: Optional maximum workers (defaults to CPU count - 1)
        
    Returns:
        Number of worker processes to spawn
    """
    cpu_count = get_cpu_count()
    default_max = max(1, cpu_count - 1)  # Leave one core for main process
    max_workers = max_workers or default_max
    
    # Calculate based on minimum batch size
    workers_needed = max(1, file_count // min_batch_size)
    
    return min(workers_needed, max_workers, cpu_count)


# =============================================================================
# Batching & Distribution
# =============================================================================

def batch_items(items: list[T], num_batches: int) -> list[list[T]]:
    """Split items into roughly equal batches for parallel processing.
    
    Args:
        items: List of items to batch
        num_batches: Number of batches to create
        
    Returns:
        List of batches, each containing a subset of items
    """
    if num_batches <= 1:
        return [items]
    
    batch_size = max(1, len(items) // num_batches)
    batches = []
    
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        if batch:
            batches.append(batch)
    
    # Distribute remainder items to avoid tiny last batch
    while len(batches) > num_batches:
        smallest = batches.pop()
        batches[-1].extend(smallest)
    
    return batches


# =============================================================================
# Result Aggregation
# =============================================================================

def aggregate_results(
    results: list[Any],
    mode: Literal["extend", "count", "dict_merge", "sum", "max", "min"]
) -> Any:
    """Aggregate results from parallel workers based on mode.
    
    Args:
        results: List of results from each worker
        mode: Aggregation strategy
            - "extend": Flatten list of lists into single list
            - "count": Sum all integer counts
            - "dict_merge": Merge all dicts (set union, list union-preserving-order, scalar override)
            - "sum": Sum all numeric values
            - "max": Return maximum value
            - "min": Return minimum value
            
    Returns:
        Aggregated result
    """
    if not results:
        if mode == "extend":
            return []
        elif mode in ("count", "sum"):
            return 0
        elif mode == "dict_merge":
            return {}
        elif mode in ("max", "min"):
            return None
        return None
    
    if mode == "extend":
        # Flatten list of lists
        aggregated = []
        for result in results:
            if isinstance(result, list):
                aggregated.extend(result)
            else:
                aggregated.append(result)
        return aggregated
    
    elif mode in ("count", "sum"):
        # Sum numeric values
        return sum(results)
    
    elif mode == "dict_merge":
        # Merge dicts with collection-aware semantics:
        # - set values: union
        # - list values: union preserving first-seen order
        # - all other values: later value overrides earlier
        merged = {}
        for result in results:
            if isinstance(result, dict):
                for key, value in result.items():
                    if key not in merged:
                        merged[key] = value
                        continue

                    existing = merged[key]
                    if isinstance(existing, set) and isinstance(value, set):
                        merged[key] = existing | value
                    elif isinstance(existing, list) and isinstance(value, list):
                        merged[key] = list(dict.fromkeys([*existing, *value]))
                    else:
                        merged[key] = value
        return merged
    
    elif mode == "max":
        return max(results)
    
    elif mode == "min":
        return min(results)
    
    else:
        raise ValueError(f"Unknown aggregation mode: {mode}")


# =============================================================================
# Core Parallel Execution
# =============================================================================

def process_files_parallel(
    files: list[str],
    worker_func: Callable[..., Any],
    mode: Literal["extend", "count", "dict_merge", "sum", "max", "min"] = "extend",
    min_files: int = DEFAULT_MIN_FILES,
    force_parallel: bool | None = None,
    legacy_env_var: str | None = None,
    timeout: int | None = BATCH_TIMEOUT_SECONDS,
    task_name: str = "file processing",
    max_retries: int = 1,
    fail_on_incomplete: bool = False,
    **worker_kwargs: Any
) -> Any:
    """Universal parallel file processor - works with ANY for-loop pattern.
    
    This function can replace virtually any `for filepath in files` loop in the
    codebase with parallel execution. It handles batching, worker coordination,
    result aggregation, and automatic fallback to sequential mode.
    
    Args:
        files: List of file paths to process
        worker_func: Function that processes a batch of files
            Signature: worker_func(files: list[str], **kwargs) -> Result
        mode: How to aggregate results from workers
            - "extend": Collect all results into flat list (default)
            - "count": Sum all counts
            - "dict_merge": Merge all dicts
            - "sum"/"max"/"min": Numeric aggregation
        min_files: Minimum files to justify parallel (default: 50)
        force_parallel: Explicit override for parallel mode selection.
            - True: always parallelize (ignores env and threshold)
            - False: always run sequentially (ignores env and threshold)
            - None: use DESLOPPIFY_PARALLEL / legacy env var / threshold auto-detection
        legacy_env_var: Optional legacy env var for backward compat
        timeout: Timeout per batch in seconds (default: 180)
        task_name: Description for logging
        max_retries: Maximum retry attempts per batch (default: 1, no retries)
        fail_on_incomplete: If True, return empty result if ANY batch fails all retries
            (default: False, returns partial results)
        **worker_kwargs: Additional kwargs passed to worker_func
        
    Returns:
        Aggregated result based on mode
        If fail_on_incomplete=True and any batch fails: returns empty result for mode
        
    Example:
        ```python
        # Replace this:
        entries = []
        for filepath in files:
            result = scan_file(filepath, zone_map)
            entries.extend(result)
        
        # With this:
        entries = process_files_parallel(
            files=files,
            worker_func=lambda batch: [scan_file(f, zone_map) for f in batch],
            mode="extend"
        )
        ```
    """
    if not files:
        return aggregate_results([], mode)
    
    # Check if parallelization is worthwhile.
    # Explicit caller intent (force_parallel) takes precedence over environment variables.
    if force_parallel is True:
        use_parallel = True
    elif force_parallel is False:
        use_parallel = False
    else:
        use_parallel = should_parallelize(
            len(files),
            min_files=min_files,
            legacy_env_var=legacy_env_var
        )
    
    if not use_parallel:
        # Sequential execution
        logger.debug(
            f"{task_name}: Sequential mode for {len(files)} files "
            f"(below threshold of {min_files})"
        )
        result = worker_func(files, **worker_kwargs)
        return result
    
    # Parallel execution
    workers = calculate_workers(len(files))
    batches = batch_items(files, workers)
    
    logger.debug(
        f"{task_name}: Parallel mode for {len(files)} files "
        f"({len(batches)} batches, {workers} workers, max_retries={max_retries})"
    )
    
    results = []
    shared_executor = _PERSISTENT_POOL.get()

    if shared_executor is not None:
        logger.debug(
            f"{task_name}: Reusing persistent pool ({workers} planned workers, "
            f"{len(batches)} batches)"
        )

    def _run_with_executor(
        executor: concurrent.futures.ProcessPoolExecutor,
    ) -> tuple[list[Any], set[int]]:
        local_results: list[Any] = []
        permanently_failed: set[int] = set()

        # Initialize retry tracking
        batch_attempts: dict[int, int] = {idx: 1 for idx in range(len(batches))}
        batches_to_process: list[tuple[int, list[str]]] = [
            (idx, batch) for idx, batch in enumerate(batches)
        ]

        # Process batches with retry logic
        while batches_to_process:
            # Submit current batch set
            futures = {
                executor.submit(worker_func, batch, **worker_kwargs): (batch_idx, batch)
                for batch_idx, batch in batches_to_process
            }

            # Collect results and identify failures
            successful_batches: list[tuple[int, Any]] = []
            failed_batches: list[tuple[int, list[str]]] = []

            try:
                for future in concurrent.futures.as_completed(futures, timeout=timeout):
                    batch_idx, batch = futures[future]
                    try:
                        result = future.result()
                        successful_batches.append((batch_idx, result))
                        logger.debug(
                            f"{task_name}: Batch {batch_idx} completed "
                            f"(attempt {batch_attempts[batch_idx]})"
                        )
                    except concurrent.futures.process.BrokenProcessPool:
                        logger.warning(
                            f"{task_name}: Worker process crashed (BrokenProcessPool), "
                            f"falling back to sequential mode"
                        )
                        raise
                    except Exception as exc:
                        # Check if we should retry
                        if batch_attempts[batch_idx] < max_retries:
                            logger.warning(
                                f"{task_name}: Batch {batch_idx} error "
                                f"(attempt {batch_attempts[batch_idx]}/{max_retries}): {exc}. "
                                f"Retrying..."
                            )
                            failed_batches.append((batch_idx, batch))
                            batch_attempts[batch_idx] += 1
                        else:
                            logger.error(
                                f"{task_name}: Batch {batch_idx} failed all {max_retries} "
                                f"attempts: {exc}",
                                exc_info=True,
                            )
                            permanently_failed.add(batch_idx)

                            # Check if it's a pickling error and fall back immediately
                            if isinstance(exc, (TypeError, AttributeError, pickle.PicklingError)):
                                raise

            except concurrent.futures.TimeoutError:
                # Timeout - mark remaining futures as needing retry
                for future, (batch_idx, batch) in futures.items():
                    if not future.done():
                        if batch_attempts[batch_idx] < max_retries:
                            logger.warning(
                                f"{task_name}: Batch {batch_idx} timeout "
                                f"(attempt {batch_attempts[batch_idx]}/{max_retries}). "
                                f"Retrying..."
                            )
                            failed_batches.append((batch_idx, batch))
                            batch_attempts[batch_idx] += 1
                        else:
                            logger.error(
                                f"{task_name}: Batch {batch_idx} failed all {max_retries} "
                                f"attempts: timeout"
                            )
                            permanently_failed.add(batch_idx)

            # Add successful results
            for _, result in successful_batches:
                local_results.append(result)

            # Update batches to retry
            batches_to_process = failed_batches

            if batches_to_process:
                logger.debug(
                    f"{task_name}: Retrying {len(batches_to_process)} failed batches..."
                )

        return local_results, permanently_failed
    
    try:
        if shared_executor is not None:
            results, permanently_failed = _run_with_executor(shared_executor)
        else:
            with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
                results, permanently_failed = _run_with_executor(executor)
            
        # Check if any batch failed all retry attempts
        if permanently_failed and fail_on_incomplete:
            logger.error(
                f"{task_name}: {len(permanently_failed)} batches failed all {max_retries} "
                f"attempts. fail_on_incomplete=True, returning empty result. "
                f"Failed batch IDs: {sorted(permanently_failed)}"
            )
            # Return empty result based on mode
            return aggregate_results([], mode)

        elif permanently_failed:
            logger.warning(
                f"{task_name}: {len(permanently_failed)} batches failed all {max_retries} "
                f"attempts, returning partial results. Failed batch IDs: {sorted(permanently_failed)}"
            )
                
    except (TypeError, AttributeError, pickle.PicklingError, 
            concurrent.futures.process.BrokenProcessPool) as exc:
        if shared_executor is not None and isinstance(exc, concurrent.futures.process.BrokenProcessPool):
            logger.warning(
                f"{task_name}: Invalidating persistent parallel pool after BrokenProcessPool"
            )
            _PERSISTENT_POOL.set(None)
            try:
                shared_executor.shutdown(wait=False, cancel_futures=True)
            except RuntimeError:
                pass
        # Pickle errors or broken process pool on Windows - fall back to sequential
        logger.warning(
            f"{task_name}: Parallel execution failed ({exc.__class__.__name__}), "
            f"falling back to sequential mode. Common cause: worker_func or "
            f"its arguments can't be pickled/imported on Windows."
        )
        result = worker_func(files, **worker_kwargs)
        return result
    
    # Aggregate results based on mode
    return aggregate_results(results, mode)


# =============================================================================
# Specialized Helpers (Security, Zone Handling)
# =============================================================================

def extract_batch_zones(
    batch_files: list[str],
    zone_map: FileZoneMap | None,
) -> dict | None:
    """Extract zone data for specific batch files only.
    
    This is an optimization: instead of passing the entire project zone map
    (potentially thousands of files) to every worker process, we extract only
    the zone information for the files in this specific batch.
    
    Performance impact:
    - Memory: ~50 zones per worker vs thousands (40-400x reduction)
    - CPU: No reconstruction needed (Zone enums pickle directly)
    - IPC: ~5KB vs 2MB serialization overhead per worker
    
    Args:
        batch_files: Files in this specific batch (~20-50 files)
        zone_map: Full project zone map (could be thousands of files)
        
    Returns:
        Dict of {filepath: Zone} for batch files only, or None
    """
    if zone_map is None:
        return None
    
    return {
        filepath: zone_map.get(filepath)
        for filepath in batch_files
    }


# =============================================================================
# Backward Compatibility Exports
# =============================================================================

# These maintain backward compatibility with existing code
batch_files = batch_items  # Alias for consistency
parallel_map = process_files_parallel  # Legacy name


__all__ = [
    # Core API
    "process_files_parallel",
    "persistent_parallel_pool",
    "should_parallelize",
    "calculate_workers",
    "batch_items",
    "aggregate_results",
    
    # Configuration
    "check_parallel_override",
    "get_cpu_count",
    
    # Specialized helpers
    "extract_batch_zones",
    
    # Backward compatibility
    "batch_files",
    "parallel_map",
]
