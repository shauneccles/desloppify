"""Tests for retry/aggregation behavior in the parallel execution framework."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any, cast
from unittest.mock import patch

import pytest

from desloppify.engine.parallel_utils import (
    MAX_PROCESS_WORKERS,
    aggregate_results,
    calculate_workers,
    persistent_parallel_pool,
    process_files_parallel,
)


_FLAKY_CALL_COUNT: dict[str, int] = defaultdict(int)


def flaky_worker_impl(files: list[str], **kwargs) -> list[str]:
    """Fails once for batches containing file_5 or file_15, then succeeds."""
    batch_key = str(sorted(files))
    _FLAKY_CALL_COUNT[batch_key] += 1
    if _FLAKY_CALL_COUNT[batch_key] == 1 and any(
        "file_5" in f or "file_15" in f for f in files
    ):
        raise RuntimeError(f"Simulated transient failure for batch of {len(files)}")
    return [f.upper() for f in files]


def always_failing_worker_impl(files: list[str], **kwargs) -> list[str]:
    raise RuntimeError(f"Always fails for batch with {len(files)} files")


def one_bad_batch_worker_impl(files: list[str], **kwargs) -> list[str]:
    if any("file_15" in f for f in files):
        raise RuntimeError("Permanent batch failure")
    return [f.upper() for f in files]


def dict_merge_worker_impl(files: list[str], **kwargs) -> dict:
    return {
        "names": set(files),
        "ordered": list(files),
    }


def dict_merge_mixed_worker_impl(files: list[str], **kwargs) -> dict:
    return {
        "names": set(files),
        "ordered": list(files),
        "batch_markers": [files[0]],
        "scalar_batch_size": len(files),
    }

@pytest.fixture
def test_files() -> list[str]:
    return [f"file_{i}.py" for i in range(20)]


@pytest.fixture
def flaky_worker() -> Callable[..., object]:
    _FLAKY_CALL_COUNT.clear()
    return flaky_worker_impl


@pytest.fixture
def always_failing_worker() -> Callable[..., object]:
    return always_failing_worker_impl


@pytest.fixture
def one_bad_batch_worker() -> Callable[..., object]:
    return one_bad_batch_worker_impl


@pytest.fixture
def dict_merge_worker() -> Callable[..., object]:
    return dict_merge_worker_impl


@pytest.fixture
def dict_merge_mixed_worker() -> Callable[..., object]:
    return dict_merge_mixed_worker_impl


def test_retry_recovers_from_transient_failures(test_files: list[str], flaky_worker) -> None:
    result = process_files_parallel(
        files=test_files,
        worker_func=flaky_worker,
        mode="extend",
        max_retries=3,
        fail_on_incomplete=False,
        min_files=5,
        task_name="RetryTest",
    )
    assert len(result) == len(test_files)
    assert set(result) == {f.upper() for f in test_files}


def test_fail_on_incomplete_returns_empty_on_permanent_failures(
    test_files: list[str], always_failing_worker
) -> None:
    result = process_files_parallel(
        files=test_files,
        worker_func=always_failing_worker,
        mode="extend",
        max_retries=2,
        fail_on_incomplete=True,
        min_files=5,
        task_name="FailOnIncompleteTest",
    )
    assert result == []


def test_partial_results_returned_when_incomplete_allowed(
    test_files: list[str], one_bad_batch_worker
) -> None:
    with patch("desloppify.engine.parallel_utils.calculate_workers", return_value=2):
        result = process_files_parallel(
            files=test_files,
            worker_func=one_bad_batch_worker,
            mode="extend",
            max_retries=1,
            fail_on_incomplete=False,
            min_files=5,
            task_name="PartialResultsTest",
        )

    assert 0 < len(result) < len(test_files)
    assert all(item.endswith(".PY") for item in result)


def test_default_behavior_backwards_compatible(test_files: list[str]) -> None:
    def simple_worker(files: list[str], **kwargs) -> list[str]:
        return [f.upper() for f in files]

    result = process_files_parallel(
        files=test_files,
        worker_func=simple_worker,
        mode="extend",
        min_files=5,
        task_name="BackwardCompatTest",
    )

    assert len(result) == len(test_files)


def test_dict_merge_unions_set_values() -> None:
    """dict_merge should union set values from different worker outputs."""
    merged = aggregate_results(
        [{"name": {"a.py", "b.py"}}, {"name": {"b.py", "c.py"}}],
        "dict_merge",
    )
    assert merged == {"name": {"a.py", "b.py", "c.py"}}


def test_dict_merge_unions_list_values_preserving_order() -> None:
    """dict_merge should union list values while preserving first-seen order."""
    merged = aggregate_results(
        [{"name": ["a.py", "b.py"]}, {"name": ["b.py", "c.py"]}],
        "dict_merge",
    )
    assert merged == {"name": ["a.py", "b.py", "c.py"]}


def test_dict_merge_end_to_end_across_multiple_batches(dict_merge_worker) -> None:
    """process_files_parallel dict_merge should merge outputs from multiple batches."""
    files = [f"item_{i}.py" for i in range(15)]

    with patch("desloppify.engine.parallel_utils.calculate_workers", return_value=3):
        result = process_files_parallel(
            files=files,
            worker_func=dict_merge_worker,
            mode="dict_merge",
            force_parallel=True,
            task_name="DictMergeE2E",
        )

    assert isinstance(result, dict)
    assert result["names"] == set(files)
    assert len(result["ordered"]) == len(files)
    assert set(result["ordered"]) == set(files)


def test_dict_merge_end_to_end_mixed_values_across_batches(dict_merge_mixed_worker) -> None:
    """dict_merge E2E should handle set/list union and scalar override together."""
    files = [f"item_{i}.py" for i in range(16)]

    with patch("desloppify.engine.parallel_utils.calculate_workers", return_value=3):
        result = process_files_parallel(
            files=files,
            worker_func=dict_merge_mixed_worker,
            mode="dict_merge",
            force_parallel=True,
            task_name="DictMergeMixedE2E",
        )

    # Set and list values should merge across all batches.
    assert result["names"] == set(files)
    assert set(result["ordered"]) == set(files)
    assert len(result["ordered"]) == len(files)
    assert len(result["batch_markers"]) == 3

    # Scalar keys are override-only by contract (value from whichever batch merged last).
    assert result["scalar_batch_size"] in {5, 6}

def test_aggregate_results_raises_for_unknown_mode() -> None:
    with pytest.raises(ValueError, match="Unknown aggregation mode"):
        aggregate_results([1, 2, 3], cast(Any, "unknown"))


def test_calculate_workers_respects_global_process_cap() -> None:
    with patch("desloppify.engine.parallel_utils.get_cpu_count", return_value=64):
        workers = calculate_workers(file_count=10_000)
    assert workers == MAX_PROCESS_WORKERS


def test_persistent_parallel_pool_respects_global_process_cap() -> None:
    with (
        patch("desloppify.engine.parallel_utils.get_cpu_count", return_value=64),
        patch("desloppify.engine.parallel_utils.concurrent.futures.ProcessPoolExecutor") as mock_pool,
    ):
        with persistent_parallel_pool():
            pass

    assert mock_pool.call_args.kwargs["max_workers"] == MAX_PROCESS_WORKERS
