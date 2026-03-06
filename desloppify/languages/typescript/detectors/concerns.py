"""Mixed concerns detection (UI + data fetching + transforms in one file)."""

from __future__ import annotations

import orjson
import logging
import re
from pathlib import Path
from typing import Any

from desloppify.base.discovery.file_paths import rel

from desloppify.base.discovery.source import find_tsx_files
from desloppify.base.output.fallbacks import log_best_effort_failure
from desloppify.base.output.terminal import colorize, print_table
from desloppify.base.discovery.paths import get_project_root
from desloppify.engine.parallel_utils import process_files_parallel

logger = logging.getLogger(__name__)


# ── Parallel Processing Support ─────────────────────────────────────────────


def _process_concern_file(filepath: str) -> dict[str, Any] | None:
    """Process a single TSX file for mixed concerns detection."""
    try:
        p = (
            Path(filepath)
            if Path(filepath).is_absolute()
            else get_project_root() / filepath
        )
        content = p.read_text()
        loc = len(content.splitlines())
        if loc < 100:
            return None

        concerns = []

        # UI rendering
        has_jsx = bool(re.search(r"return\s*\(?\s*<", content))
        if has_jsx:
            concerns.append("jsx_rendering")

        # Data fetching
        has_fetch = bool(
            re.search(r"useQuery|useMutation|supabase\.|fetch\(|axios", content)
        )
        if has_fetch:
            concerns.append("data_fetching")

        # Direct supabase calls (should be in hooks/services)
        has_supabase = bool(re.search(r"supabase\.\w+\.\w+\.\w+", content))
        if has_supabase:
            concerns.append("direct_supabase")

        # Heavy data transformation
        transform_patterns = len(
            re.findall(r"\.(map|filter|reduce|sort|flatMap)\s*\(", content)
        )
        if transform_patterns >= 3:
            concerns.append(f"data_transforms({transform_patterns})")

        # Event handler definitions (>5 = probably doing too much)
        handler_count = len(re.findall(r"(?:const|function)\s+handle\w+", content))
        if handler_count >= 5:
            concerns.append(f"handlers({handler_count})")

        # Flag if 3+ concern types in one file
        if len(concerns) >= 3:
            return {
                "file": filepath,
                "loc": loc,
                "concerns": concerns,
                "concern_count": len(concerns),
            }
    except (OSError, UnicodeDecodeError) as exc:
        log_best_effort_failure(
            logger, f"read TSX concern candidate {filepath}", exc
        )
    return None


def _concerns_batch_worker(filepaths: list[str]) -> list[dict[str, Any]]:
    """Worker function to process a batch of TSX files for mixed concerns."""
    results = []
    for filepath in filepaths:
        result = _process_concern_file(filepath)
        if result is not None:
            results.append(result)
    return results


def detect_mixed_concerns(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Find files that mix UI rendering with data fetching, state management, and business logic.

    Heuristic: a .tsx file that has both JSX returns AND direct API/supabase calls
    or both UI components AND heavy data transformation.

    Returns (entries, total_files_checked).
    """
    files = find_tsx_files(path)
    entries = process_files_parallel(
        files=files,
        worker_func=_concerns_batch_worker,
        mode="extend",
        min_files=100,
        task_name="typescript mixed concerns",
    )
    if not isinstance(entries, list):
        entries = [entries]
    return sorted(entries, key=lambda e: -e["concern_count"]), len(files)


def cmd_concerns(args: Any) -> None:
    entries, _ = detect_mixed_concerns(Path(args.path))
    if args.json:
        print(orjson.dumps({"count": len(entries), "entries": entries}, option=orjson.OPT_INDENT_2).decode("utf-8"))
        return
    if not entries:
        print(colorize("No mixed-concern files found.", "green"))
        return
    print(colorize(f"\nMixed concerns: {len(entries)} files\n", "bold"))
    rows = []
    for e in entries[: args.top]:
        rows.append([rel(e["file"]), str(e["loc"]), ", ".join(e["concerns"])])
    print_table(["File", "LOC", "Concerns"], rows, [55, 5, 50])
