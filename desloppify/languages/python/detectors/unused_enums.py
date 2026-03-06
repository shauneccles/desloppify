"""Detect enum classes with zero external imports."""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from desloppify.base.discovery.file_paths import rel

from desloppify.base.discovery.source import find_py_files
from desloppify.engine.parallel_utils import process_files_parallel

logger = logging.getLogger(__name__)

_ENUM_BASES = {"StrEnum", "IntEnum", "Enum"}


def detect_unused_enums(path: Path) -> tuple[list[dict], int]:
    """Find enum classes that are never imported by any other file.

    Returns ``(entries, total_files_checked)``.
    Each entry has: file, name, line, member_count.
    """
    # Phase 1: collect enum definitions per file.
    files = find_py_files(path)
    enum_defs: dict[str, list[dict]] = {}
    imports_by_file: dict[str, set[str]] = {}

    batch_results = process_files_parallel(
        files=files,
        worker_func=_unused_enums_batch_worker,
        mode="extend",
        min_files=100,
        task_name="python unused enums",
        scan_root=str(path.resolve()),
    )
    normalized_batches = batch_results if isinstance(batch_results, list) else [batch_results]
    for batch in normalized_batches:
        if not isinstance(batch, dict):
            continue
        for filepath, defs in batch.get("enum_defs", {}).items():
            if isinstance(defs, list):
                enum_defs[filepath] = defs
        for filepath, imported in batch.get("imports_by_file", {}).items():
            if isinstance(imported, list):
                imports_by_file[filepath] = set(imported)

    if not enum_defs:
        return [], len(files)

    # Phase 2: check which enums are imported by at least one *other* file.
    all_enum_names: dict[str, list[str]] = {}  # enum_name → [defining_files]
    for filepath, defs in enum_defs.items():
        for d in defs:
            all_enum_names.setdefault(d["name"], []).append(filepath)

    externally_imported: set[str] = set()
    for filepath, imported in imports_by_file.items():
        for name in imported:
            if name in all_enum_names and filepath not in all_enum_names[name]:
                externally_imported.add(name)

    # Phase 3: report enums with zero external imports.
    entries: list[dict] = []
    for filepath, defs in enum_defs.items():
        rpath = rel(filepath)
        for d in defs:
            if d["name"] not in externally_imported:
                entries.append({
                    "file": rpath,
                    "name": d["name"],
                    "line": d["line"],
                    "member_count": d["member_count"],
                })

    entries.sort(key=lambda entry: (entry["file"], entry["name"], entry["line"]))
    return entries, len(files)


def _extract_unused_enum_file(filepath: str, scan_root: str) -> dict:
    try:
        root = Path(scan_root)
        p = Path(filepath) if Path(filepath).is_absolute() else root / filepath
        content = p.read_text()
    except (OSError, UnicodeDecodeError):
        return {"filepath": filepath, "enums": [], "imports": []}

    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError:
        return {"filepath": filepath, "enums": [], "imports": []}

    file_enums: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        is_enum = any(
            (isinstance(base, ast.Name) and base.id in _ENUM_BASES)
            or (isinstance(base, ast.Attribute) and base.attr in _ENUM_BASES)
            for base in node.bases
        )
        if not is_enum:
            continue
        member_count = sum(
            1
            for child in node.body
            if isinstance(child, ast.Assign)
            and any(isinstance(target, ast.Name) for target in child.targets)
        )
        file_enums.append(
            {"name": node.name, "line": node.lineno, "member_count": member_count}
        )

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[-1])

    return {
        "filepath": filepath,
        "enums": file_enums,
        "imports": sorted(imported),
    }


def _unused_enums_batch_worker(files: list[str], scan_root: str) -> dict:
    enum_defs: dict[str, list[dict]] = {}
    imports_by_file: dict[str, list[str]] = {}
    for filepath in files:
        result = _extract_unused_enum_file(filepath, scan_root)
        enums = result.get("enums", [])
        imports = result.get("imports", [])
        source_file = str(result.get("filepath", filepath))
        if enums:
            enum_defs[source_file] = enums
        imports_by_file[source_file] = imports
    return {"enum_defs": enum_defs, "imports_by_file": imports_by_file}


__all__ = ["detect_unused_enums"]
