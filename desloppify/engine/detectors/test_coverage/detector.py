"""Test coverage gap detection — static analysis of test mapping and quality."""

from __future__ import annotations

from typing import TypeAlias

from desloppify.engine.detectors.coverage.mapping import (
    analyze_test_quality,
    build_test_import_index,
    import_based_mapping,
    naming_based_mapping,
    transitive_coverage,
)
from desloppify.engine.policy.zones import FileZoneMap
from desloppify.engine.parallel_utils import (
    batch_items,
    calculate_workers,
    process_files_parallel,
)

from .discovery import (
    _discover_scorable_and_tests,
    _no_tests_issues,
    _normalize_graph_paths,
)
from .issues import (
    _generate_issues_for_scorable,
    _generate_issues,
)

_TEST_COVERAGE_PARALLEL_MIN_FILES = 6000
TestCoverageImportsIndex: TypeAlias = dict[str, set[str]]


def _estimate_issue_generation_weight(
    filepath: str,
    *,
    graph: dict,
    directly_tested: set[str],
    transitively_tested: set[str],
    complexity_map: dict[str, float] | None,
) -> float:
    node = graph.get(filepath, {})
    importer_count = float(node.get("importer_count", 0) or 0)
    complexity = float((complexity_map or {}).get(filepath, 0.0) or 0.0)

    weight = 1.0 + min(importer_count, 300.0) * 0.03 + min(complexity, 40.0) * 0.25
    if filepath in directly_tested:
        weight += 4.0
    elif filepath in transitively_tested:
        weight += 1.5
    return weight


def _plan_balanced_issue_generation_batches(
    scorable_files: list[str],
    *,
    graph: dict,
    directly_tested: set[str],
    transitively_tested: set[str],
    complexity_map: dict[str, float] | None,
    worker_count: int | None = None,
) -> list[list[str]]:
    if not scorable_files:
        return []

    workers = worker_count or calculate_workers(len(scorable_files))
    template_batches = batch_items(scorable_files, workers)
    capacities = [len(batch) for batch in template_batches if batch]
    if not capacities:
        return [scorable_files]

    planned_batches: list[list[str]] = [[] for _ in capacities]
    loads: list[float] = [0.0 for _ in capacities]
    remaining = capacities[:]

    weighted_files = sorted(
        (
            (
                filepath,
                _estimate_issue_generation_weight(
                    filepath,
                    graph=graph,
                    directly_tested=directly_tested,
                    transitively_tested=transitively_tested,
                    complexity_map=complexity_map,
                ),
            )
            for filepath in scorable_files
        ),
        key=lambda item: (-item[1], item[0]),
    )

    for filepath, weight in weighted_files:
        candidates = [idx for idx, slots in enumerate(remaining) if slots > 0]
        if not candidates:
            planned_batches[-1].append(filepath)
            loads[-1] += weight
            continue
        target_index = min(candidates, key=lambda idx: (loads[idx], -remaining[idx], idx))
        planned_batches[target_index].append(filepath)
        loads[target_index] += weight
        remaining[target_index] -= 1

    return [batch for batch in planned_batches if batch]


def _test_coverage_issue_batch_worker(
    files: list[str],
    *,
    directly_tested: set[str],
    transitively_tested: set[str],
    test_quality: dict[str, dict],
    graph: dict,
    lang_name: str,
    parsed_imports_by_test: TestCoverageImportsIndex,
    complexity_map: dict[str, float] | None,
) -> list[dict]:
    return _generate_issues_for_scorable(
        set(files),
        directly_tested,
        transitively_tested,
        test_quality,
        graph,
        lang_name,
        parsed_imports_by_test=parsed_imports_by_test,
        complexity_map=complexity_map,
    )


def detect_test_coverage(
    graph: dict,
    zone_map: FileZoneMap,
    lang_name: str,
    extra_test_files: set[str] | None = None,
    complexity_map: dict[str, float] | None = None,
) -> tuple[list[dict], int]:
    graph = _normalize_graph_paths(graph)

    production_files, test_files, scorable, potential = _discover_scorable_and_tests(
        graph=graph,
        zone_map=zone_map,
        lang_name=lang_name,
        extra_test_files=extra_test_files,
    )
    if not scorable:
        return [], 0

    if not test_files:
        entries = _no_tests_issues(scorable, graph, lang_name, complexity_map)
        return entries, potential

    directly_tested = import_based_mapping(
        graph,
        test_files,
        production_files,
        lang_name,
    )
    directly_tested |= naming_based_mapping(test_files, production_files, lang_name)

    transitively_tested = transitive_coverage(directly_tested, graph, production_files)
    test_quality = analyze_test_quality(test_files, lang_name)

    if potential >= _TEST_COVERAGE_PARALLEL_MIN_FILES:
        scorable_files = sorted(scorable)
        planned_batches = _plan_balanced_issue_generation_batches(
            scorable_files,
            graph=graph,
            directly_tested=directly_tested,
            transitively_tested=transitively_tested,
            complexity_map=complexity_map,
        )
        ordered_scorable = [filepath for batch in planned_batches for filepath in batch]
        production_scope = set(scorable) | set(directly_tested) | set(transitively_tested)
        parsed_imports_by_test = build_test_import_index(
            set(test_quality.keys()),
            production_scope,
            lang_name,
        )
        return (
            process_files_parallel(
                files=ordered_scorable,
                worker_func=_test_coverage_issue_batch_worker,
                mode="extend",
                min_files=_TEST_COVERAGE_PARALLEL_MIN_FILES,
                task_name="test coverage issue generation",
                directly_tested=directly_tested,
                transitively_tested=transitively_tested,
                test_quality=test_quality,
                graph=graph,
                lang_name=lang_name,
                parsed_imports_by_test=parsed_imports_by_test,
                complexity_map=complexity_map,
            ),
            potential,
        )

    entries = _generate_issues(
        scorable,
        directly_tested,
        transitively_tested,
        test_quality,
        graph,
        lang_name,
        complexity_map=complexity_map,
    )
    return entries, potential
