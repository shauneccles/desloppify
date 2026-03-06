"""Issue construction helpers for the test-coverage detector."""

from __future__ import annotations

import os

from desloppify.engine.detectors.coverage.mapping import (
    build_test_import_index,
    get_test_files_for_prod,
)

from .metrics import _COMPLEXITY_TIER_UPGRADE, _file_loc, _loc_weight

_QUALITY_ISSUE_PRIORITY = {
    "assertion_free": 5,
    "placeholder_smoke": 4,
    "smoke": 3,
    "over_mocked": 2,
    "snapshot_heavy": 1,
}

def _generate_issues(
    scorable: set[str],
    directly_tested: set[str],
    transitively_tested: set[str],
    test_quality: dict[str, dict],
    graph: dict,
    lang_name: str,
    complexity_map: dict[str, float] | None = None,
) -> list[dict]:
    test_files = set(test_quality.keys())
    production_scope = set(scorable) | set(directly_tested) | set(transitively_tested)
    parsed_imports_by_test = build_test_import_index(
        test_files,
        production_scope,
        lang_name,
    )

    return _generate_issues_for_scorable(
        scorable,
        directly_tested,
        transitively_tested,
        test_quality,
        graph,
        lang_name,
        parsed_imports_by_test=parsed_imports_by_test,
        complexity_map=complexity_map,
    )


def _generate_issues_for_scorable(
    scorable: set[str],
    directly_tested: set[str],
    transitively_tested: set[str],
    test_quality: dict[str, dict],
    graph: dict,
    lang_name: str,
    *,
    parsed_imports_by_test: dict[str, set[str]],
    complexity_map: dict[str, float] | None = None,
) -> list[dict]:
    entries: list[dict] = []
    cmap = complexity_map or {}
    test_files = set(test_quality.keys())

    for filepath in scorable:
        loc = _file_loc(filepath)
        importer_count = graph.get(filepath, {}).get("importer_count", 0)
        loc_weight = _loc_weight(loc)

        if filepath in directly_tested:
            related_tests = get_test_files_for_prod(
                filepath,
                test_files,
                graph,
                lang_name,
                parsed_imports_by_test=parsed_imports_by_test,
            )
            issue = _select_direct_test_quality_issue(
                prod_file=filepath,
                related_tests=related_tests,
                test_quality=test_quality,
                loc_weight=loc_weight,
            )
            if issue:
                entries.append(issue)
            continue

        complexity = cmap.get(filepath, 0)
        if filepath in transitively_tested:
            entries.append(
                _transitive_coverage_gap_issue(
                    file_path=filepath,
                    loc=loc,
                    importer_count=importer_count,
                    loc_weight=loc_weight,
                    complexity=complexity,
                )
            )
            continue

        entries.append(
            _untested_module_issue(
                file_path=filepath,
                loc=loc,
                importer_count=importer_count,
                loc_weight=loc_weight,
                complexity=complexity,
            )
        )

    return entries

def _quality_issue_rank(quality_kind: object) -> int:
    """Return severity rank for a quality issue kind (higher = more severe)."""
    if not isinstance(quality_kind, str):
        return 0
    return _QUALITY_ISSUE_PRIORITY.get(quality_kind, 0)

def _select_direct_test_quality_issue(
    *,
    prod_file: str,
    related_tests: list[str],
    test_quality: dict[str, dict],
    loc_weight: float,
) -> dict | None:
    """Return one representative quality issue for a directly-tested module."""
    has_adequate_direct_test = False
    selected: tuple[int, str, dict] | None = None

    for test_file in sorted(related_tests):
        quality = test_quality.get(test_file)
        if quality is None:
            continue
        quality_kind = quality.get("quality")
        issue = _quality_issue_item(
            prod_file=prod_file,
            test_file=test_file,
            quality=quality,
            loc_weight=loc_weight,
        )
        if issue is None:
            if quality_kind in {"adequate", "thorough"}:
                has_adequate_direct_test = True
            continue

        rank = _quality_issue_rank(quality_kind)
        if selected is None:
            selected = (rank, test_file, issue)
            continue
        prev_rank, prev_file, _ = selected
        if rank > prev_rank or (rank == prev_rank and test_file < prev_file):
            selected = (rank, test_file, issue)

    if has_adequate_direct_test:
        return None
    if selected is None:
        return None
    return selected[2]

def _quality_issue_item(
    *,
    prod_file: str,
    test_file: str,
    quality: dict,
    loc_weight: float,
) -> dict | None:
    basename = os.path.basename(test_file)
    quality_kind = quality.get("quality")
    if quality_kind == "assertion_free":
        return {
            "file": prod_file,
            "name": f"assertion_free::{basename}",
            "tier": 3,
            "confidence": "medium",
            "summary": (
                f"Assertion-free test: {basename} has "
                f"{quality['test_functions']} test functions but 0 assertions"
            ),
            "detail": {
                "kind": "assertion_free_test",
                "test_file": test_file,
                "test_functions": quality["test_functions"],
                "loc_weight": loc_weight,
            },
        }
    if quality_kind == "placeholder_smoke":
        return {
            "file": prod_file,
            "name": f"placeholder::{basename}",
            "tier": 2,
            "confidence": "high",
            "summary": (
                f"Placeholder smoke test: {basename} relies on tautological assertions "
                "and likely inflates coverage confidence"
            ),
            "detail": {
                "kind": "placeholder_test",
                "test_file": test_file,
                "assertions": quality["assertions"],
                "test_functions": quality["test_functions"],
                "loc_weight": loc_weight,
            },
        }
    if quality_kind == "smoke":
        return {
            "file": prod_file,
            "name": f"shallow::{basename}",
            "tier": 3,
            "confidence": "medium",
            "summary": (
                f"Shallow tests: {basename} has {quality['assertions']} assertions across "
                f"{quality['test_functions']} test functions"
            ),
            "detail": {
                "kind": "shallow_tests",
                "test_file": test_file,
                "assertions": quality["assertions"],
                "test_functions": quality["test_functions"],
                "loc_weight": loc_weight,
            },
        }
    if quality_kind == "over_mocked":
        return {
            "file": prod_file,
            "name": f"over_mocked::{basename}",
            "tier": 3,
            "confidence": "low",
            "summary": (
                f"Over-mocked tests: {basename} has "
                f"{quality['mocks']} mocks vs {quality['assertions']} assertions"
            ),
            "detail": {
                "kind": "over_mocked",
                "test_file": test_file,
                "mocks": quality["mocks"],
                "assertions": quality["assertions"],
                "loc_weight": loc_weight,
            },
        }
    if quality_kind == "snapshot_heavy":
        return {
            "file": prod_file,
            "name": f"snapshot_heavy::{basename}",
            "tier": 3,
            "confidence": "low",
            "summary": (
                f"Snapshot-heavy tests: {basename} has {quality['snapshots']} snapshots vs "
                f"{quality['assertions']} assertions"
            ),
            "detail": {
                "kind": "snapshot_heavy",
                "test_file": test_file,
                "snapshots": quality["snapshots"],
                "assertions": quality["assertions"],
                "loc_weight": loc_weight,
            },
        }
    return None

def _transitive_coverage_gap_issue(
    *,
    file_path: str,
    loc: int,
    importer_count: int,
    loc_weight: float,
    complexity: float,
) -> dict:
    is_complex = complexity >= _COMPLEXITY_TIER_UPGRADE
    detail: dict = {
        "kind": "transitive_only",
        "loc": loc,
        "importer_count": importer_count,
        "loc_weight": loc_weight,
    }
    if is_complex:
        detail["complexity_score"] = complexity
    return {
        "file": file_path,
        "name": "transitive_only",
        "tier": 2 if (importer_count >= 10 or is_complex) else 3,
        "confidence": "medium",
        "summary": (
            f"No direct tests ({loc} LOC, {importer_count} importers) "
            "— covered only via imports from tested modules"
        ),
        "detail": detail,
    }

def _untested_module_issue(
    *,
    file_path: str,
    loc: int,
    importer_count: int,
    loc_weight: float,
    complexity: float,
) -> dict:
    is_complex = complexity >= _COMPLEXITY_TIER_UPGRADE
    if importer_count >= 10 or is_complex:
        detail: dict = {
            "kind": "untested_critical",
            "loc": loc,
            "importer_count": importer_count,
            "loc_weight": loc_weight,
        }
        if is_complex:
            detail["complexity_score"] = complexity
        return {
            "file": file_path,
            "name": "untested_critical",
            "tier": 2,
            "confidence": "high",
            "summary": (
                f"Untested critical module ({loc} LOC, {importer_count} importers) "
                "— high blast radius"
            ),
            "detail": detail,
        }
    return {
        "file": file_path,
        "name": "untested_module",
        "tier": 3,
        "confidence": "high",
        "summary": f"Untested module ({loc} LOC, {importer_count} importers)",
        "detail": {
            "kind": "untested_module",
            "loc": loc,
            "importer_count": importer_count,
            "loc_weight": loc_weight,
        },
    }


__all__ = [
    "_generate_issues",
    "_quality_issue_item",
    "_quality_issue_rank",
    "_select_direct_test_quality_issue",
    "_transitive_coverage_gap_issue",
    "_untested_module_issue",
    "_generate_issues_for_scorable",
]
