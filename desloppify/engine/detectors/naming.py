"""Naming consistency analysis: flag directories with mixed filename conventions."""

from collections import defaultdict
from pathlib import Path

from desloppify.base.discovery.file_paths import rel
from desloppify.engine.parallel_utils import process_files_parallel


def _classify_convention(filename: str) -> str | None:
    """Classify a filename (without extension) into a naming convention."""
    stem = filename.rsplit(".", 1)[0] if "." in filename else filename
    if not stem:
        return None

    if "-" in stem and stem == stem.lower():
        return "kebab-case"
    if stem[0].isupper() and "-" not in stem:
        return "PascalCase"
    if stem[0].islower() and any(c.isupper() for c in stem) and "-" not in stem:
        return "camelCase"
    if "_" in stem and stem == stem.lower():
        return "snake_case"
    if stem.islower() and "-" not in stem:
        return "flat_lower"
    return None


def detect_naming_inconsistencies(
    path: Path,
    file_finder,
    skip_names: set[str] | None = None,
    skip_dirs: set[str] | None = None,
) -> tuple[list[dict], int]:
    """Find directories where minority naming convention is significant.

    Thresholds: minority must have >= 5 files (absolute) and >= 15% of total (proportional).
    """
    all_skip_names = skip_names or set()
    all_skip_dirs = skip_dirs or set()
    files = file_finder(path)

    batch_results = process_files_parallel(
        files=files,
        worker_func=_naming_batch_worker,
        mode="dict_merge",
        min_files=100,
        task_name="naming inconsistency detection",
        skip_names=all_skip_names,
        skip_dirs=all_skip_dirs,
    )
    dir_files: dict[str, dict[str, list[str]]] = {}
    if isinstance(batch_results, dict):
        for dirname, conventions in batch_results.items():
            if isinstance(conventions, dict):
                dir_files[dirname] = {
                    convention: list(files_by_conv)
                    for convention, files_by_conv in conventions.items()
                    if isinstance(files_by_conv, list)
                }

    entries = []
    for dirname, conventions in dir_files.items():
        if len(conventions) < 2:
            continue

        sorted_conventions = sorted(conventions.items(), key=lambda x: -len(x[1]))
        majority_name, majority_files = sorted_conventions[0]
        total = sum(len(fs) for fs in conventions.values())

        for conv_name, conv_files in sorted_conventions[1:]:
            if len(conv_files) < 5:
                continue
            if len(conv_files) / total < 0.15:
                continue

            entries.append(
                {
                    "directory": rel(dirname),
                    "majority": majority_name,
                    "majority_count": len(majority_files),
                    "minority": conv_name,
                    "minority_count": len(conv_files),
                    "total_files": total,
                    "outliers": sorted(conv_files[:10]),
                }
            )

    return sorted(entries, key=lambda e: -e["minority_count"]), len(dir_files)


def _naming_batch_worker(
    files: list[str],
    skip_names: set[str],
    skip_dirs: set[str],
) -> dict[str, dict[str, list[str]]]:
    dir_files: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))

    for filepath in files:
        p = Path(filepath)
        dirname = str(p.parent)
        rdir = rel(dirname)
        filename = p.name

        if filename in skip_names:
            continue
        if rdir in skip_dirs:
            continue

        convention = _classify_convention(filename)
        if convention:
            dir_files[dirname][convention].append(filename)

    return {
        dirname: {conv: sorted(names) for conv, names in conventions.items()}
        for dirname, conventions in dir_files.items()
    }
