"""Dynamic import discovery for Python dependency hints."""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from desloppify.base.discovery.source import find_py_files
from desloppify.engine.parallel_utils import process_files_parallel

from .deps_resolution import resolve_absolute_import

logger = logging.getLogger(__name__)


def _iter_dynamic_import_targets(
    filepath: str,
    root: Path,
) -> set[str]:
    targets: set[str] = set()
    py_file = Path(filepath) if Path(filepath).is_absolute() else root / filepath
    try:
        source = py_file.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_file))
    except (SyntaxError, OSError) as exc:
        logger.debug(
            "Skipping unreadable file %s in dynamic import scan: %s",
            py_file,
            exc,
        )
        return targets

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "import_module"
            and isinstance(func.value, ast.Name)
            and func.value.id == "importlib"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            continue

        spec = node.args[0].value
        resolved = resolve_absolute_import(spec, root)
        if resolved:
            targets.add(resolved)
        else:
            targets.add(spec)

    return targets


def _dynamic_import_batch_worker(files: list[str], *, root: str) -> list[str]:
    root_path = Path(root)
    batch_targets: set[str] = set()
    for filepath in files:
        batch_targets |= _iter_dynamic_import_targets(filepath, root_path)
    return sorted(batch_targets)


def find_python_dynamic_imports(
    path: Path,
    extensions: list[str],
    candidate_files: set[str] | None = None,
) -> set[str]:
    """Find module specifiers referenced by ``importlib.import_module`` calls."""
    del extensions
    scan_files = sorted(candidate_files) if candidate_files else find_py_files(path)
    if not scan_files:
        return set()

    targets = process_files_parallel(
        files=scan_files,
        worker_func=_dynamic_import_batch_worker,
        mode="extend",
        min_files=100,
        task_name="python dynamic import scan",
        root=str(path),
    )
    return set(targets) if isinstance(targets, list) else set()


__all__ = ["find_python_dynamic_imports"]
