"""TypeScript/React code smell detection.

Defines TS-specific smell rules and orchestrates multi-line smell detection.
"""

import json
import logging
import re
from pathlib import Path

from desloppify.base.discovery.source import (

    find_source_files,

    find_ts_files,

)
from desloppify.base.output.fallbacks import log_best_effort_failure
from desloppify.base.discovery.paths import get_project_root
from desloppify.languages.typescript.detectors._smell_detectors import (
    _detect_async_no_await,
    _detect_catch_return_default,
    _detect_dead_useeffects,
    _detect_empty_if_chains,
    _detect_error_no_throw,
    _detect_high_cyclomatic_complexity,
    _detect_monster_functions,
    _detect_nested_closures,
    _detect_stub_functions,
    _detect_swallowed_errors,
    _detect_switch_no_default,
    _detect_window_globals,
)
from desloppify.languages.typescript.detectors._smell_helpers import (
    _build_ts_line_state,
    _FileContext,
    _ts_match_is_in_string,
)

logger = logging.getLogger(__name__)

_MULTI_LINE_DETECTORS = (
    _detect_async_no_await,
    _detect_catch_return_default,
    _detect_dead_useeffects,
    _detect_empty_if_chains,
    _detect_error_no_throw,
    _detect_high_cyclomatic_complexity,
    _detect_monster_functions,
    _detect_nested_closures,
    _detect_stub_functions,
    _detect_swallowed_errors,
    _detect_switch_no_default,
    _detect_window_globals,
)


TS_SMELL_CHECKS = [
    {
        "id": "empty_catch",
        "label": "Empty catch blocks",
        "pattern": r"catch\s*\([^)]*\)\s*\{\s*\}",
        "severity": "high",
    },
    {
        "id": "any_type",
        "label": "Explicit `any` types",
        "pattern": r":\s*any\b|<\s*any\b|,\s*any\b(?=\s*(?:,|>))",
        "severity": "medium",
    },
    {
        "id": "ts_ignore",
        "label": "@ts-ignore / @ts-expect-error",
        "pattern": r"//\s*@ts-(?:ignore|expect-error)",
        "severity": "medium",
    },
    {
        "id": "ts_nocheck",
        "label": "@ts-nocheck disables all type checking",
        "pattern": r"^\s*//\s*@ts-nocheck",
        "severity": "high",
    },
    {
        "id": "non_null_assert",
        "label": "Non-null assertions (!.)",
        "pattern": r"\w+!\.",
        "severity": "low",
    },
    {
        "id": "hardcoded_color",
        "label": "Hardcoded color values",
        "pattern": r"""(?:color|background|border|fill|stroke)\s*[:=]\s*['"]#[0-9a-fA-F]{3,8}['"]""",
        "severity": "medium",
    },
    {
        "id": "hardcoded_rgb",
        "label": "Hardcoded rgb/rgba",
        "pattern": r"rgba?\(\s*\d+",
        "severity": "medium",
    },
    {
        "id": "async_no_await",
        "label": "Async functions without await",
        "pattern": None,  # multi-line analysis
        "severity": "medium",
    },
    {
        "id": "magic_number",
        "label": "Magic numbers (>1000 in logic)",
        "pattern": r"(?:===?|!==?|>=?|<=?|[+\-*/])\s*\d{4,}",
        "severity": "low",
    },
    {
        "id": "console_error_no_throw",
        "label": "console.error without throw/return",
        "pattern": None,  # multi-line analysis
        "severity": "medium",
    },
    {
        "id": "empty_if_chain",
        "label": "Empty if/else chains",
        "pattern": None,  # multi-line analysis
        "severity": "high",
    },
    {
        "id": "dead_useeffect",
        "label": "useEffect with empty body",
        "pattern": None,  # multi-line analysis
        "severity": "high",
    },
    {
        "id": "swallowed_error",
        "label": "Catch blocks that only log (swallowed errors)",
        "pattern": None,  # multi-line analysis
        "severity": "medium",
    },
    {
        "id": "hardcoded_url",
        "label": "Hardcoded URL in source code",
        "pattern": r"""(?:['\"])https?://[^\s'\"]+(?:['\"])""",
        "severity": "medium",
    },
    {
        "id": "todo_fixme",
        "label": "TODO/FIXME/HACK comments",
        "pattern": r"//\s*(?:TODO|FIXME|HACK|XXX)",
        "severity": "low",
    },
    {
        "id": "debug_tag",
        "label": "Vestigial debug tag in log/print",
        "pattern": r"""(?:['"`])\[([A-Z][A-Z0-9_]{2,})\]\s""",
        "severity": "low",
    },
    {
        "id": "monster_function",
        "label": "Monster function (>150 LOC)",
        # Detected via brace-tracking
        "pattern": None,
        "severity": "high",
    },
    {
        "id": "stub_function",
        "label": "Stub function (body is empty/return-only)",
        # Detected via brace-tracking
        "pattern": None,
        "severity": "low",
    },
    {
        "id": "voided_symbol",
        "label": "Dead internal code (void-suppressed unused symbol)",
        "pattern": r"^\s*void\s+[a-zA-Z_]\w*\s*;?\s*$",
        "severity": "medium",
    },
    {
        "id": "window_global",
        "label": "Window global escape hatch (window.__*)",
        "pattern": None,  # multi-line analysis — regex needs alternation
        "severity": "medium",
    },
    {
        "id": "workaround_tag",
        "label": "Workaround tag in comment ([PascalCaseTag])",
        "pattern": r"//.*\[([A-Z][a-z]+(?:[A-Z][a-z]+)+)\]",
        "severity": "low",
    },
    {
        "id": "catch_return_default",
        "label": "Catch block returns default object (silent failure)",
        "pattern": None,  # multi-line brace-tracked
        "severity": "high",
    },
    {
        "id": "as_any_cast",
        "label": "`as any` type casts",
        "pattern": r"\bas\s+any\b",
        "severity": "medium",
    },
    {
        "id": "sort_no_comparator",
        "label": ".sort() without comparator function",
        "pattern": r"\.sort\(\s*\)",
        "severity": "medium",
    },
    {
        "id": "switch_no_default",
        "label": "Switch without default case",
        "pattern": None,  # multi-line brace-tracked
        "severity": "low",
    },
    {
        "id": "nested_closure",
        "label": "Deeply nested closures — extract to module level",
        "pattern": None,
        "severity": "medium",
    },
    {
        "id": "high_cyclomatic_complexity",
        "label": "High cyclomatic complexity (>15 branches)",
        "pattern": None,
        "severity": "medium",
    },
    {
        "id": "css_monolith",
        "label": "Large stylesheet file (300+ LOC)",
        "pattern": None,  # non-TS asset scan
        "severity": "medium",
    },
    {
        "id": "css_important_overuse",
        "label": "Heavy !important usage in stylesheet",
        "pattern": None,  # non-TS asset scan
        "severity": "low",
    },
    {
        "id": "docs_scripts_drift",
        "label": "README missing key package scripts",
        "pattern": None,  # non-TS asset scan
        "severity": "low",
    },
]


def _script_is_documented(readme_text: str, script_name: str) -> bool:
    escaped = re.escape(script_name)
    command_patterns = [
        rf"\bnpm\s+(?:run\s+)?{escaped}\b",
        rf"\bpnpm\s+{escaped}\b",
        rf"\byarn\s+{escaped}\b",
        rf"\bbun\s+run\s+{escaped}\b",
    ]
    if any(re.search(pattern, readme_text, flags=re.IGNORECASE) for pattern in command_patterns):
        return True
    return bool(re.search(rf"`{escaped}`", readme_text))


def _detect_non_ts_asset_smells(path: Path, smell_counts: dict[str, list[dict]]) -> int:
    """Scan adjacent non-TS assets (CSS/docs) for common repo-health smells."""
    scanned_files = 0
    css_files = find_source_files(path, [".css", ".scss", ".sass", ".less"])
    scanned_files += len(css_files)

    for filepath in css_files:
        try:
            full = Path(filepath) if Path(filepath).is_absolute() else get_project_root() / filepath
            content = full.read_text()
            lines = content.splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            log_best_effort_failure(logger, f"read stylesheet smell candidate {filepath}", exc)
            continue

        if len(lines) >= 300:
            smell_counts["css_monolith"].append(
                {
                    "file": filepath,
                    "line": 1,
                    "content": f"{len(lines)} LOC stylesheet",
                }
            )

        important_count = content.count("!important")
        if important_count >= 8:
            first_line = next(
                (idx + 1 for idx, line in enumerate(lines) if "!important" in line),
                1,
            )
            smell_counts["css_important_overuse"].append(
                {
                    "file": filepath,
                    "line": first_line,
                    "content": f"{important_count} !important declarations",
                }
            )

    readme_path = get_project_root() / "README.md"
    package_path = get_project_root() / "package.json"
    if not readme_path.is_file() or not package_path.is_file():
        return scanned_files

    scanned_files += 1
    try:
        readme_text = readme_path.read_text()
        package_payload = orjson.loads(package_path.read_text())
    except (OSError, UnicodeDecodeError, orjson.JSONDecodeError) as exc:
        log_best_effort_failure(logger, "read package/readme for docs drift smell", exc)
        return scanned_files

    scripts = package_payload.get("scripts")
    if not isinstance(scripts, dict):
        return scanned_files

    key_scripts = [
        script for script in ("dev", "build", "test", "lint", "typecheck") if script in scripts
    ]
    if len(key_scripts) < 2:
        return scanned_files

    missing = [script for script in key_scripts if not _script_is_documented(readme_text, script)]
    if len(missing) >= 2:
        smell_counts["docs_scripts_drift"].append(
            {
                "file": "README.md",
                "line": 1,
                "content": f"Missing script docs: {', '.join(missing[:5])}",
            }
        )
    return scanned_files


def _process_ts_smell_file(filepath: str, checks: list[dict]) -> dict[str, list[dict]]:
    """Process a single TypeScript file for smell detection.
    
    Returns:
        Dict mapping smell IDs to list of matches
    """
    smell_counts: dict[str, list[dict]] = {s["id"]: [] for s in checks}
    
    if "node_modules" in filepath or ".d.ts" in filepath:
        return smell_counts
    
    try:
        p = (
            Path(filepath)
            if Path(filepath).is_absolute()
            else PROJECT_ROOT / filepath
        )
        content = p.read_text()
        lines = content.splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        log_best_effort_failure(
            logger, f"read TypeScript smell candidate {filepath}", exc
        )
        return smell_counts

    # Build line state for string/comment filtering
    line_state = _build_ts_line_state(lines)

    # Regex-based smells
    for check in checks:
        if check["pattern"] is None:
            continue
        for i, line in enumerate(lines):
            # Skip lines inside block comments or template literals
            if i in line_state:
                continue
            m = re.search(check["pattern"], line)
            if not m:
                continue
            # Check if match is inside a single-line string or comment
            if _ts_match_is_in_string(line, m.start()):
                continue
            # Skip URLs assigned to module-level constants
            if check["id"] == "hardcoded_url" and re.match(
                r"^(?:export\s+)?(?:const|let|var)\s+[A-Z_][A-Z0-9_]*\s*=",
                line.strip(),
            ):
                continue
            smell_counts[check["id"]].append(
                {
                    "file": filepath,
                    "line": i + 1,
                    "content": line.strip()[:100],
                }
            )

    # Multi-line smell helpers (brace-tracked)
    _detect_async_no_await(filepath, content, lines, smell_counts)
    _detect_error_no_throw(filepath, lines, smell_counts)
    _detect_empty_if_chains(filepath, lines, smell_counts)
    _detect_dead_useeffects(filepath, lines, smell_counts)
    _detect_swallowed_errors(filepath, content, lines, smell_counts)
    _detect_monster_functions(filepath, lines, smell_counts)
    _detect_dead_functions(filepath, lines, smell_counts)
    _detect_window_globals(filepath, lines, line_state, smell_counts)
    _detect_catch_return_default(filepath, content, smell_counts)
    _detect_switch_no_default(filepath, content, smell_counts)
    _detect_nested_closures(filepath, lines, smell_counts)
    _detect_high_cyclomatic_complexity(filepath, lines, smell_counts)
    
    return smell_counts


def _ts_smells_batch_worker(files: list[str], checks: list[dict]) -> dict[str, list[dict]]:
    """Worker function for TypeScript smell detection."""
    combined_smell_counts: dict[str, list[dict]] = {s["id"]: [] for s in checks}
    
    for filepath in files:
        file_smell_counts = _process_ts_smell_file(filepath, checks)
        for smell_id, matches in file_smell_counts.items():
            combined_smell_counts[smell_id].extend(matches)
    
    return combined_smell_counts


def detect_smells(path: Path) -> tuple[list[dict], int]:
    """Detect TypeScript/React code smell patterns across the codebase.

    Returns (entries, total_files_checked).
    """
    checks = TS_SMELL_CHECKS
    files = find_ts_files(path)

    for filepath in files:
        if "node_modules" in filepath or ".d.ts" in filepath:
            continue
        try:
            p = (
                Path(filepath)
                if Path(filepath).is_absolute()
                else get_project_root() / filepath
            )
            content = p.read_text()
            lines = content.splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            log_best_effort_failure(
                logger, f"read TypeScript smell candidate {filepath}", exc
            )
            continue

        # Build line state for string/comment filtering
        line_state = _build_ts_line_state(lines)
        ctx = _FileContext(filepath, content, lines, line_state)

        # Regex-based smells
        for check in checks:
            if check["pattern"] is None:
                continue
            for i, line in enumerate(lines):
                # Skip lines inside block comments or template literals
                if i in line_state:
                    continue
                m = re.search(check["pattern"], line)
                if not m:
                    continue
                # Check if match is inside a single-line string or comment
                if _ts_match_is_in_string(line, m.start()):
                    continue
                # Skip URLs assigned to module-level constants
                if check["id"] == "hardcoded_url" and re.match(
                    r"^(?:export\s+)?(?:const|let|var)\s+[A-Z_][A-Z0-9_]*\s*=",
                    line.strip(),
                ):
                    continue
                smell_counts[check["id"]].append(
                    {
                        "file": filepath,
                        "line": i + 1,
                        "content": line.strip()[:100],
                    }
                )

        # Multi-line smell detectors (brace-tracked, uniform ctx signature)
        for detector in _MULTI_LINE_DETECTORS:
            detector(ctx, smell_counts)

    non_ts_files = _detect_non_ts_asset_smells(path, smell_counts)

    # Build summary entries sorted by severity then count
    severity_order = {"high": 0, "medium": 1, "low": 2}
    entries = []
    for check in checks:
        matches = smell_counts[check["id"]]
        if matches:
            entries.append(
                {
                    "id": check["id"],
                    "label": check["label"],
                    "severity": check["severity"],
                    "count": len(matches),
                    "files": len(set(m["file"] for m in matches)),
                    "matches": matches[:50],
                }
            )
    entries.sort(key=lambda e: (severity_order.get(e["severity"], 9), -e["count"]))
    return entries, len(files) + non_ts_files
