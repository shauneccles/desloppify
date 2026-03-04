# Universal Parallel Execution Framework

## Overview

A truly modular system for parallelizing ANY `for filepath in files` loop across the entire codebase. Single environment variable (`DESLOPPIFY_PARALLEL`) controls all multiprocessing.

## Key Features

- **Universal API**: Works with any file processing loop
- **Flexible aggregation**: Supports list extend, count, dict merge, sum, max, min
- **Auto-detection**: Intelligently decides when parallelization is worthwhile
- **Type-safe**: Generic typing for result aggregation
- **Composable**: Easy to add custom processing logic
- **Windows-compatible**: Uses `concurrent.futures.ProcessPoolExecutor`

## Architecture

### Centralized Module

**Location**: `desloppify/engine/_parallel_utils.py`

All parallel execution utilities are now in ONE place:
- Core API: `process_files_parallel()`
- Config: `should_parallelize()`, `calculate_workers()`
- Aggregation: `aggregate_results()`
- Batching: `batch_items()`

### Backward Compatibility

**Old location**: `desloppify/engine/detectors/_parallel_utils.py`  
**Status**: Re-exports from centralized module (no breaking changes)

## Usage Guide

### Simple Case: List Aggregation

**Before** (Sequential):
```python
entries = []
for filepath in files:
    result = process_file(filepath)
    entries.extend(result)
```

**After** (Parallel):
```python
from desloppify.engine._parallel_utils import process_files_parallel

entries = process_files_parallel(
    files=files,
    worker_func=lambda batch: [process_file(f) for f in batch],
    mode="extend"
)
```

### Count Aggregation

**Before**:
```python
count = 0
for filepath in files:
    count += analyze_file(filepath)
```

**After**:
```python
count = process_files_parallel(
    files=files,
    worker_func=lambda batch: sum(analyze_file(f) for f in batch),
    mode="count"
)
```

### Dict Merging

**Before**:
```python
result_dict = {}
for filepath in files:
    data = extract_data(filepath)
    result_dict.update(data)
```

**After**:
```python
def worker(batch):
    batch_dict = {}
    for f in batch:
        batch_dict.update(extract_data(f))
    return batch_dict

result_dict = process_files_parallel(
    files=files,
    worker_func=worker,
    mode="dict_merge"
)
```

### Complex Processing with Context

**Before**:
```python
entries = []
for filepath in files:
    entry = complex_analysis(filepath, zone_map, config)
    if entry:
        entries.append(entry)
```

**After**:
```python
def worker(batch, zone_map, config):
    results = []
    for f in batch:
        entry = complex_analysis(f, zone_map, config)
        if entry:
            results.append(entry)
    return results

entries = process_files_parallel(
    files=files,
    worker_func=worker,
    mode="extend",
    zone_map=zone_map,
    config=config
)
```

## Environment Variables

### Global Control (Recommended)

```bash
# Enable ALL parallel execution
export DESLOPPIFY_PARALLEL=true
desloppify scan

# Disable ALL parallel execution
export DESLOPPIFY_PARALLEL=false
desloppify scan

# Auto-detect (default) - uses parallel for 50+ files
desloppify scan
```

## Configuration Options

### Aggregation Modes

| Mode | Use Case | Example |
|------|----------|---------|
| `"extend"` | Flatten list of lists | Collecting findings from all files |
| `"count"` | Sum integers | Counting total issues |
| `"dict_merge"` | Merge dicts | Building dependency graphs |
| `"sum"` | Sum numerics | Calculating total complexity |
| `"max"` | FindCommand failed. max value | Finding worst-case metric |
| `"min"` | Find min value | Finding best-case metric |

### Threshold Tuning

```python
# Default: 50 files minimum for parallel
entries = process_files_parallel(
    files=files,
    worker_func=worker,
    min_files=50  # Adjust based on per-file cost
)

# High per-file cost (e.g., tree-sitter parsing)
min_files=20  # Parallelize sooner

# Low per-file cost (e.g., regex matching)
min_files=100  # Wait for more files
```

### Timeout Control

```python
# Default: 180 seconds per batch
entries = process_files_parallel(
    files=files,
    worker_func=worker,
    timeout=300  # 5 minutes for slow operations
)
```

## Migration Examples

### Example 1: Complexity Detector

**File**: `desloppify/engine/detectors/complexity.py`

**Before**:
```python
def detect_complexity(path, signals, file_finder, threshold, min_loc):
    files = file_finder(path)
    entries = []
    for filepath in files:
        entry = analyze_complexity(filepath, signals, threshold, min_loc)
        if entry:
            entries.append(entry)
    return sorted(entries, key=lambda e: -e["score"]), len(files)
```

**After**:
```python
from desloppify.engine._parallel_utils import process_files_parallel

def _complexity_worker(files, path, signals, threshold, min_loc):
    entries = []
    for filepath in files:
        entry = _process_file_for_complexity(filepath, path, signals, threshold, min_loc)
        if entry:
            entries.append(entry)
    return entries

def detect_complexity(path, signals, file_finder, threshold, min_loc):
    files = file_finder(path)
    
    entries = process_files_parallel(
        files=files,
        worker_func=_complexity_worker,
        mode="extend",
        task_name="complexity detection",
        path=path,
        signals=signals,
        threshold=threshold,
        min_loc=min_loc
    )
    
    return sorted(entries, key=lambda e: -e["score"]), len(files)
```

### Example 2: Security Detector

**File**: `desloppify/engine/detectors/security/detector.py`

Already parallelized! Uses the new framework.

### Example 3: Language-Specific Detectors

**Pattern** for all `desloppify/languages/*/detectors/*.py` files:

1. Extract single-file logic into `_process_file_*()` function
2. Create `_*_worker()` that processes a batch
3. Replace loop with `process_files_parallel()`

## Performance Impact

### Benchmark Results

**Hardware**: AMD Ryzen 9 5900X (12 cores, 24 threads), Windows 11  
**Codebase**: desloppify self-scan (674 Python files)

| Mode | Time | CPU Usage | Speedup |
|------|------|-----------|---------|
| Sequential | 44.1s | 43.8s | 1.0x |
| Parallel | 35.4s | 77.5s | **1.25x** |

**Key Insight**: CPU usage increased 77% (77.5s vs 43.8s), proving true multi-core utilization!

### When to Parallelize

✅ **Good candidates** (high per-file cost):
- Tree-sitter parsing (TypeScript, Python AST)
- Regex-heavy analysis (code smells, patterns)
- File I/O + processing (complexity, security)
- Cross-file analysis (dependency graphs)

❌ **Poor candidates** (low per-file cost):
- Simple string matching
- File listing/stat operations
- In-memory data structure iteration

## Testing

### Unit Tests

```bash
# Test parallel utilities
uv run pytest desloppify/tests/detectors/security/test_parallel.py -xvs

# Verify no regressions
uv run pytest desloppify/tests/detectors/ -xvs
```

### Integration Tests

```bash
# Full scan with parallel enabled
export DESLOPPIFY_PARALLEL=true
uv run desloppify scan

# Full scan with parallel disabled
export DESLOPPIFY_PARALLEL=false
uv run desloppify scan
```

### Benchmarking

```bash
# Compare performance
hyperfine --warmup 1 --runs 3 \
  -n "sequential" "DESLOPPIFY_PARALLEL=false uv run desloppify scan" \
  -n "parallel" "DESLOPPIFY_PARALLEL=true uv run desloppify scan"
```

## Troubleshooting

### Windows Multiprocessing Issues

**Symptom**: `AttributeError: module '__main__' has no attribute 'X'`

**Cause**: Windows spawn mode can't pickle objects defined in `__main__`

**Solution**: Ensure worker functions and data are defined in modules, not __main__

### Worker Timeouts

**Symptom**: `concurrent.futures.TimeoutError`

**Solution**: Increase timeout parameter
```python
entries = process_files_parallel(
    files=files,
    worker_func=worker,
    timeout=300  # Increase from default 180s
)
```

### Memory Issues

**Symptom**: Out of memory with large file lists

**Solution**: Reduce batch size
```python
from desloppify.engine._parallel_utils import calculate_workers

# Force more batches with smaller size
workers = calculate_workers(len(files), min_batch_size=5)
```

## Migration Checklist

For each `for filepath in files` loop:

- [ ] Extract single-file processing into standalone function  
- [ ] Create worker function that processes a batch
- [ ] Replace loop with `process_files_parallel()`
- [ ] Choose appropriate aggregation mode
- [ ] Test with `DESLOPPIFY_PARALLEL=true` and `false`
- [ ] Verify results match sequential version
- [ ] Benchmark performance improvement
- [ ] Update any affected tests

## API Reference

### Core Functions

```python
process_files_parallel(
    files: list[str],
    worker_func: Callable,
    mode: Literal["extend", "count", "dict_merge", "sum", "max", "min"],
    min_files: int = 50,
    legacy_env_var: str | None = None,
    timeout: int | None = 180,
    task_name: str = "file processing",
    **worker_kwargs
) -> Any
```

```python
should_parallelize(
    file_count: int,
    min_files: int = 50,
    legacy_env_var: str | None = None
) -> bool
```

```python
calculate_workers(
    file_count: int,
    min_batch_size: int = 10,
    max_workers: int | None = None
) -> int
```

```python
aggregate_results(
    results: list[Any],
    mode: Literal["extend", "count", "dict_merge", "sum", "max", "min"]
) -> Any
```

## Next Steps

1. **Migrate remaining detectors** (56 loops identified)
2. **Optimize batch sizes** per detector type  
3. **Add per-detector benchmark tests**
4. **Document performance characteristics**
5. **Consider async I/O** for I/O-bound operations

## References

- Centralized module: `desloppify/engine/_parallel_utils.py`
- Example migration: `desloppify/engine/detectors/complexity.py`
- Tests: `desloppify/tests/detectors/security/test_parallel.py`
- Benchmark docs: `docs/PARALLEL_SECURITY_SCANNING.md`
