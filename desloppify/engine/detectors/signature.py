"""Signature variance detection — same function name, different signatures across modules."""

from __future__ import annotations

from collections import defaultdict

from desloppify.engine.detectors.base import FunctionInfo
from desloppify.engine.parallel_utils import process_files_parallel

_SIGNATURE_PARALLEL_MIN_GROUPS = 120

# Names that are legitimately polymorphic — skip them
_ALLOWLIST = {
    "__init__",
    "__repr__",
    "__str__",
    "__eq__",
    "__hash__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__len__",
    "__iter__",
    "__next__",
    "__enter__",
    "__exit__",
    "__call__",
    "__getattr__",
    "__setattr__",
    "__getitem__",
    "__setitem__",
    "__delitem__",
    "__contains__",
    "main",
    "setup",
    "teardown",
    "configure",
    "run",
    "handle",
    "setUp",
    "tearDown",
    "setUpClass",
    "tearDownClass",
    "get",
    "post",
    "put",
    "delete",
    "patch",  # HTTP methods
}


def _signature_group_keys(name: str) -> list[tuple[str, str]]:
    """Return grouping keys: exact name and selected naming-pattern buckets."""
    keys = [("name", name)]
    normalized = name.lstrip("_")
    if normalized.startswith("phase_") and len(normalized) > len("phase_"):
        keys.append(("pattern", "phase_*"))
    return keys


def _analyze_signature_group(
    group_type: str,
    group_name: str,
    fns: list[FunctionInfo],
    *,
    min_occurrences: int,
) -> dict | None:
    distinct_files = set(getattr(f, "file", "") for f in fns)
    if len(distinct_files) < min_occurrences:
        return None

    variants = []
    for fn in fns:
        params = [p for p in fn.params if p not in ("self", "cls")]
        variants.append(
            {
                "file": getattr(fn, "file", ""),
                "line": fn.line,
                "params": params,
                "param_count": len(params),
                "return_annotation": getattr(fn, "return_annotation", None),
            }
        )

    param_signatures = set()
    for variant in variants:
        param_signatures.add(tuple(variant["params"]))
    return_signatures = {
        str(variant["return_annotation"]).strip()
        for variant in variants
        if variant.get("return_annotation")
    }
    has_param_variance = len(param_signatures) >= 2
    has_return_variance = len(return_signatures) >= 2

    if not has_param_variance and not has_return_variance:
        return None

    return {
        "name": group_name,
        "group_type": group_type,
        "occurrences": len(fns),
        "files": sorted(distinct_files),
        "file_count": len(distinct_files),
        "variants": variants,
        "signature_count": len(param_signatures),
        "return_signature_count": len(return_signatures),
        "has_param_variance": has_param_variance,
        "has_return_variance": has_return_variance,
    }


def _signature_variance_batch_worker(
    group_keys: list[tuple[str, str]],
    *,
    by_group: dict[tuple[str, str], list[FunctionInfo]],
    min_occurrences: int,
) -> list[dict]:
    batch_entries: list[dict] = []
    for group_type, group_name in group_keys:
        entry = _analyze_signature_group(
            group_type,
            group_name,
            by_group[(group_type, group_name)],
            min_occurrences=min_occurrences,
        )
        if entry is not None:
            batch_entries.append(entry)
    return batch_entries


def detect_signature_variance(
    functions: list[FunctionInfo],
    min_occurrences: int = 3,
) -> tuple[list[dict], int]:
    """Find function names appearing 3+ times across files with different signatures.

    Returns (entries, total_functions_checked).

    Each entry represents a function name group where signatures differ:
    {
        "name": str,           # function name
        "occurrences": int,    # how many definitions
        "files": list[str],    # distinct files
        "variants": list[dict] # [{file, line, params, param_count}]
    }
    """
    # Group by exact function name and select naming-pattern groups.
    by_group: dict[tuple[str, str], list[FunctionInfo]] = defaultdict(list)
    for fn in functions:
        normalized_name = fn.name.lstrip("_")
        is_phase_pattern = normalized_name.startswith("phase_")
        if fn.name.startswith("_") and not fn.name.startswith("__") and not is_phase_pattern:
            continue  # Skip private functions — expected to be independent
        if fn.name in _ALLOWLIST:
            continue
        if fn.name.startswith("test_"):
            continue  # Skip test functions
        for key in _signature_group_keys(fn.name):
            by_group[key].append(fn)

    entries: list[dict]
    if len(by_group) >= _SIGNATURE_PARALLEL_MIN_GROUPS:
        entries = process_files_parallel(
            files=list(by_group.keys()),
            worker_func=_signature_variance_batch_worker,
            mode="extend",
            min_files=_SIGNATURE_PARALLEL_MIN_GROUPS,
            task_name="signature variance analysis",
            by_group=by_group,
            min_occurrences=min_occurrences,
        )
    else:
        entries = []
        for (group_type, group_name), fns in by_group.items():
            entry = _analyze_signature_group(
                group_type,
                group_name,
                fns,
                min_occurrences=min_occurrences,
            )
            if entry is not None:
                entries.append(entry)

    entries.sort(
        key=lambda e: (
            -max(e["signature_count"], e["return_signature_count"]),
            -e["occurrences"],
            e["name"],
        )
    )
    return entries, len(functions)
