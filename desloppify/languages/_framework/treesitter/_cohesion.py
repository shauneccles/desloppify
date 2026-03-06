"""Responsibility cohesion detection via tree-sitter function extraction.

Identifies files with multiple disconnected clusters of functions —
a sign of mixed responsibilities ("dumping ground" modules).

Algorithm:
1. Extract all top-level functions in each file
2. Build an intra-file call graph (function A references function B's name)
3. Find connected components via union-find
4. Flag files with 5+ disconnected clusters
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import TYPE_CHECKING

from desloppify.engine.parallel_utils import process_files_parallel

from . import PARSE_INIT_ERRORS
from ._cache import _PARSE_CACHE
from ._extractors import _get_parser, _make_query, _node_text, _run_query, _unwrap_node

if TYPE_CHECKING:
    from desloppify.languages._framework.treesitter import TreeSitterLangSpec

logger = logging.getLogger(__name__)

# Minimum thresholds to analyze a file.
_MIN_FUNCTIONS = 8  # Don't flag files with few functions.
_MIN_CLUSTERS = 5   # Minimum disconnected clusters to flag.


def detect_responsibility_cohesion(
    file_list: list[str],
    spec: TreeSitterLangSpec,
    *,
    min_loc: int = 200,
) -> tuple[list[dict], int]:
    """Find files with disconnected function clusters.

    Returns (entries, total_files_checked).
    Each entry: {file, loc, function_count, component_count, families}.
    """
    try:
        parser, language = _get_parser(spec.grammar)
    except PARSE_INIT_ERRORS as exc:
        logger.debug("tree-sitter init failed: %s", exc)
        return [], 0

    query = _make_query(language, spec.function_query)

    batch_results = process_files_parallel(
        files=file_list,
        worker_func=_cohesion_batch_worker,
        mode="extend",
        min_files=100,
        task_name=f"tree-sitter {spec.grammar} responsibility cohesion",
        grammar=spec.grammar,
        function_query=spec.function_query,
        min_loc=min_loc,
    )
    normalized_batches = batch_results if isinstance(batch_results, list) else [batch_results]
    entries: list[dict] = []
    checked = 0
    for batch in normalized_batches:
        if not isinstance(batch, dict):
            continue
        entries.extend(batch.get("entries", []))
        checked += int(batch.get("checked", 0))

    entries.sort(key=lambda e: -e["component_count"])
    return entries, checked


def _analyze_cohesion_file(
    filepath: str,
    parser,
    grammar: str,
    query,
    min_loc: int,
) -> dict:
    cached = _PARSE_CACHE.get_or_parse(filepath, parser, grammar)
    if cached is None:
        return {"entry": None, "checked": 0}
    source, tree = cached

    loc = source.count(b"\n") + 1
    if loc < min_loc:
        return {"entry": None, "checked": 1}

    matches = _run_query(query, tree.root_node)
    functions: dict[str, str] = {}
    for _pattern_idx, captures in matches:
        func_node = _unwrap_node(captures.get("func"))
        name_node = _unwrap_node(captures.get("name"))
        if not func_node or not name_node:
            continue
        name = _node_text(name_node)
        body = source[func_node.start_byte:func_node.end_byte]
        functions[name] = body.decode("utf-8", errors="replace")

    if len(functions) < _MIN_FUNCTIONS:
        return {"entry": None, "checked": 1}

    func_names = set(functions.keys())
    adjacency: dict[str, set[str]] = defaultdict(set)
    for fn_name, body in functions.items():
        for other_name in func_names:
            if other_name == fn_name:
                continue
            if re.search(r"\b" + re.escape(other_name) + r"\b", body):
                adjacency[fn_name].add(other_name)
                adjacency[other_name].add(fn_name)

    visited: set[str] = set()
    components: list[list[str]] = []
    for fn_name in func_names:
        if fn_name in visited:
            continue
        component: list[str] = []
        queue = [fn_name]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            component.append(current)
            for neighbor in adjacency.get(current, set()):
                if neighbor not in visited:
                    queue.append(neighbor)
        components.append(component)

    if len(components) < _MIN_CLUSTERS:
        return {"entry": None, "checked": 1}

    components.sort(key=len, reverse=True)
    families = [component[0] for component in components[:8]]
    return {
        "entry": {
            "file": filepath,
            "loc": loc,
            "function_count": len(functions),
            "component_count": len(components),
            "component_sizes": [len(component) for component in components],
            "families": families,
        },
        "checked": 1,
    }


def _cohesion_batch_worker(
    files: list[str],
    grammar: str,
    function_query: str,
    min_loc: int,
) -> dict:
    parser, language = _get_parser(grammar)
    query = _make_query(language, function_query)
    entries: list[dict] = []
    checked = 0
    for filepath in files:
        result = _analyze_cohesion_file(filepath, parser, grammar, query, min_loc)
        entry = result.get("entry")
        if isinstance(entry, dict):
            entries.append(entry)
        checked += int(result.get("checked", 0))
    return {"entries": entries, "checked": checked}


__all__ = ["detect_responsibility_cohesion"]
