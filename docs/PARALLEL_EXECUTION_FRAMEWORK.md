# Parallel Execution Framework

## Scope

This document describes the current parallel runtime used by desloppify for file-batch style work.

- Core module: `desloppify/engine/parallel_utils.py`
- Core entrypoint: `process_files_parallel(...)`
- Global runtime switch: `DESLOPPIFY_PARALLEL`

It also includes CLI controls that affect parallel execution in user workflows.

## What the framework provides

- Batch splitting (`batch_items`)
- Worker count calculation (`calculate_workers`)
- Parallel/sequential mode selection (`should_parallelize`)
- Result aggregation (`aggregate_results`)
- Process execution + retries + fallback (`process_files_parallel`)
- Optional scan-lifetime executor reuse (`persistent_parallel_pool`)

## Process pool management

### Default executor lifecycle

`process_files_parallel` creates a `concurrent.futures.ProcessPoolExecutor` per call unless a persistent pool is already active.

- Worker count defaults to `max(1, cpu_count - 1)` and is bounded by file count and min batch size logic.
- Batches are submitted concurrently, then collected with `as_completed`.
- On completion, the executor is shut down by context manager exit.

### Persistent pool lifecycle

`persistent_parallel_pool(max_workers=None)` is a context manager backed by a `ContextVar`.

- If no pool exists in context, it creates one and stores it for nested calls.
- If a pool already exists, nested calls reuse it and do not create a new executor.
- On scope exit, the pool is reset in context and shut down (`wait=True`).
- Current status: used as the default wrapper around detector phase execution in `desloppify/engine/planning/scan.py`.

### Broken pool handling

If a `BrokenProcessPool` occurs while using a persistent executor:

- The persistent pool context value is invalidated.
- A best-effort shutdown is attempted with cancellation.
- The operation falls back to sequential execution for that call.

## Parallel decision model

Selection precedence inside `process_files_parallel`:

1. `force_parallel=True/False` (explicit caller override)
2. `DESLOPPIFY_PARALLEL` global env override
3. Auto-threshold (`file_count >= min_files`, default `50`)

## Defaults and constants

From `desloppify/engine/parallel_utils.py`:

- `DEFAULT_MIN_FILES = 50`
- `DEFAULT_BATCH_SIZE = 10`
- `BATCH_TIMEOUT_SECONDS = 180`
- `MAX_RETRY_ATTEMPTS = 3` (constant available to callers)

Per-call defaults in `process_files_parallel`:

- `mode="extend"`
- `timeout=180`
- `max_retries=1` (one attempt, no retries)
- `fail_on_incomplete=False`

## Retry, timeout, and failure behavior

`process_files_parallel` supports per-batch retry and timeout semantics.

- `max_retries` controls max attempts per batch.
- A timed-out batch is retried until attempts are exhausted.
- Exception failures are retried the same way, except pickling/broken-pool errors trigger fallback.
- If some batches fail permanently:
  - `fail_on_incomplete=False`: returns partial aggregated results.
  - `fail_on_incomplete=True`: returns empty aggregate for the selected mode.

### Sequential fallback triggers

The call falls back to sequential execution if parallel submission/execution fails with:

- `pickle.PicklingError`
- `concurrent.futures.process.BrokenProcessPool`

This is primarily for Windows spawn/pickling compatibility when a worker function or arguments are not importable/pickleable.

## Aggregation modes

Supported `mode` values:

- `"extend"`: flatten list results
- `"count"`: numeric sum
- `"dict_merge"`: key-wise merge with collection-aware behavior
- `"sum"`: numeric sum
- `"max"`: max value
- `"min"`: min value

`dict_merge` semantics:

- set + set => union
- list + list => order-preserving unique union
- scalar/other conflicts => later value wins

## CLI and runtime controls

### Global control for scan/detector parallelism

There is no dedicated `scan --parallel` flag today.

Use environment variable control:

- `DESLOPPIFY_PARALLEL=true|1|yes` => force parallel on
- `DESLOPPIFY_PARALLEL=false|0|no` => force parallel off
- unset/other => auto threshold behavior

Windows CLI startup also enables `multiprocessing.freeze_support()` in `desloppify/cli.py`.

### `review --run-batches` parallel controls

Review batch orchestration has separate concurrency controls (threaded subagent orchestration, not `process_files_parallel`):

- `--parallel`
- `--max-parallel-batches` (default `3`)
- `--batch-timeout-seconds` (parser default `1200`)
- `--batch-max-retries` (default `1`)
- `--batch-retry-backoff-seconds` (default `2.0`)
- `--batch-heartbeat-seconds` (default `15.0`)
- `--batch-stall-warning-seconds` (default `0`, disabled)
- `--batch-stall-kill-seconds` (default `120`)

Runtime coercion/normalization is centralized in `desloppify/app/commands/review/runtime/policy.py`.

## Usage examples

### Basic detector pattern

```python
from desloppify.engine.parallel_utils import process_files_parallel

def worker(batch: list[str], *, root: Path) -> list[dict]:
    out: list[dict] = []
    for filepath in batch:
        issue = scan_file(filepath, root=root)
        if issue:
            out.append(issue)
    return out

entries = process_files_parallel(
    files=file_list,
    worker_func=worker,
    mode="extend",
    task_name="ExampleScan",
    root=scan_root,
)
```

### Force sequential for debugging

```python
entries = process_files_parallel(
    files=file_list,
    worker_func=worker,
    force_parallel=False,
    mode="extend",
)
```

### Enable retries for flaky workloads

```python
entries = process_files_parallel(
    files=file_list,
    worker_func=worker,
    mode="extend",
    timeout=300,
    max_retries=3,
    fail_on_incomplete=False,
)
```

## Operational guidance

- Prefer module-level worker functions (not closures/lambdas) for Windows compatibility.
- Keep worker kwargs pickle-safe and small.
- For heavy shared context maps, pass batch-local subsets when possible (see `extract_batch_zones`).
- Start with `force_parallel=False` while validating detector correctness, then enable auto/forced parallel.

## Where to look in code

- Framework core: `desloppify/engine/parallel_utils.py`
- CLI bootstrap (Windows freeze support): `desloppify/cli.py`
- Scan command parser (`scan` options): `desloppify/app/cli_support/parser_groups.py`
- Review parallel parser options: `desloppify/app/cli_support/parser_groups_admin_review.py`
- Review runtime policy normalization: `desloppify/app/commands/review/runtime/policy.py`
- Example detector usage: `desloppify/engine/detectors/security/detector.py`
