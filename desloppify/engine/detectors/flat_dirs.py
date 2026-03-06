"""Flat directory detection — directories with too many source files."""

import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from desloppify.base.discovery.file_paths import resolve_scan_file
from desloppify.engine.parallel_utils import process_files_parallel

logger = logging.getLogger(__name__)

THIN_WRAPPER_NAMES = frozenset(
    {
        "components",
        "hooks",
        "utils",
        "services",
        "state",
        "contexts",
        "contracts",
        "types",
        "models",
        "adapters",
        "helpers",
        "core",
        "common",
    }
)
_DEFAULT_THIN_WRAPPER_NAMES = (
    "components",
    "hooks",
    "utils",
    "services",
    "state",
    "contexts",
    "contracts",
    "types",
    "models",
    "adapters",
    "helpers",
    "core",
    "common",
)


@dataclass(frozen=True)
class FlatDirDetectionConfig:
    """Thresholds and heuristics for flat directory detection."""

    threshold: int = 20
    child_dir_threshold: int = 10
    child_dir_weight: int = 3
    combined_threshold: int = 30
    sparse_parent_child_threshold: int = 8
    sparse_child_file_threshold: int = 1
    sparse_child_count_threshold: int = 6
    sparse_child_ratio_threshold: float = 0.7
    thin_wrapper_parent_sibling_threshold: int = 10
    thin_wrapper_max_file_count: int = 1
    thin_wrapper_max_child_dir_count: int = 1
    thin_wrapper_names: tuple[str, ...] = _DEFAULT_THIN_WRAPPER_NAMES


def format_flat_dir_summary(entry: dict) -> str:
    """Render a human-readable summary for a flat/fragmented directory entry."""
    kind = str(entry.get("kind", "overload"))
    file_count = int(entry.get("file_count", 0))
    child_dir_count = int(entry.get("child_dir_count", 0))
    combined_score = int(entry.get("combined_score", file_count))
    sparse_child_count = int(entry.get("sparse_child_count", 0))
    sparse_file_threshold = int(entry.get("sparse_child_file_threshold", 1))
    parent_sibling_count = int(entry.get("parent_sibling_count", 0))
    wrapper_item_count = int(entry.get("wrapper_item_count", 0))
    if kind == "fragmented":
        return (
            "Directory fragmentation: "
            f"{file_count} files, {child_dir_count} child dirs "
            f"(combined {combined_score}); "
            f"{sparse_child_count}/{child_dir_count} child dirs have <= "
            f"{sparse_file_threshold} file(s) — consider flattening/grouping"
        )
    if kind == "overload_fragmented":
        return (
            "Directory overload: "
            f"{file_count} files, {child_dir_count} child dirs "
            f"(combined {combined_score}); "
            f"{sparse_child_count}/{child_dir_count} child dirs have <= "
            f"{sparse_file_threshold} file(s)"
        )
    if kind == "thin_wrapper":
        return (
            "Thin wrapper directory: "
            f"{file_count} files, {child_dir_count} child dirs "
            f"({wrapper_item_count} item) in parent with "
            f"{parent_sibling_count} sibling dirs — consider flattening"
        )
    return (
        "Directory overload: "
        f"{file_count} files, {child_dir_count} child dirs "
        f"(combined {combined_score}) — consider grouping by domain"
    )


def _resolve_detection_settings(
    *,
    threshold: int,
    config: FlatDirDetectionConfig | None,
    child_dir_threshold: int,
    child_dir_weight: int,
    combined_threshold: int,
    sparse_parent_child_threshold: int,
    sparse_child_file_threshold: int,
    sparse_child_count_threshold: int,
    sparse_child_ratio_threshold: float,
    thin_wrapper_parent_sibling_threshold: int,
    thin_wrapper_max_file_count: int,
    thin_wrapper_max_child_dir_count: int,
    thin_wrapper_names: tuple[str, ...],
) -> FlatDirDetectionConfig:
    if config is not None:
        return config
    return FlatDirDetectionConfig(
        threshold=threshold,
        child_dir_threshold=child_dir_threshold,
        child_dir_weight=child_dir_weight,
        combined_threshold=combined_threshold,
        sparse_parent_child_threshold=sparse_parent_child_threshold,
        sparse_child_file_threshold=sparse_child_file_threshold,
        sparse_child_count_threshold=sparse_child_count_threshold,
        sparse_child_ratio_threshold=sparse_child_ratio_threshold,
        thin_wrapper_parent_sibling_threshold=thin_wrapper_parent_sibling_threshold,
        thin_wrapper_max_file_count=thin_wrapper_max_file_count,
        thin_wrapper_max_child_dir_count=thin_wrapper_max_child_dir_count,
        thin_wrapper_names=thin_wrapper_names,
    )


def _build_dir_stats(
    scan_root: Path,
    files: list[str],
) -> tuple[Counter[str], dict[str, set[str]]]:
    batch_results = process_files_parallel(
        files=files,
        worker_func=_flat_dirs_batch_worker,
        mode="extend",
        min_files=100,
        task_name="flat directory stats",
        scan_root=str(scan_root),
    )

    dir_counts: Counter[str] = Counter()
    child_dirs: dict[str, set[str]] = {}
    normalized_batches = batch_results if isinstance(batch_results, list) else [batch_results]
    for batch in normalized_batches:
        if not isinstance(batch, dict):
            continue
        for dirname, count in batch.get("dir_counts", {}).items():
            dir_counts[str(dirname)] += int(count)
        for parent, children in batch.get("child_dirs", {}).items():
            child_dirs.setdefault(str(parent), set()).update(str(child) for child in children)

    return dir_counts, child_dirs


def _flat_dirs_batch_worker(files: list[str], scan_root: str) -> dict:
    root = Path(scan_root)
    dir_counts: dict[str, int] = {}
    child_dirs: dict[str, set[str]] = {}
    for filepath in files:
        try:
            resolved_file = resolve_scan_file(filepath, scan_root=root).resolve()
            parent_path = resolved_file.parent
            parent_rel = parent_path.relative_to(root)
        except (OSError, ValueError):
            continue

        parent = str((root / parent_rel).resolve())
        dir_counts[parent] = dir_counts.get(parent, 0) + 1
        parts = parent_rel.parts
        for idx in range(len(parts) - 1):
            ancestor = (root / Path(*parts[: idx + 1])).resolve()
            child = (root / Path(*parts[: idx + 2])).resolve()
            ancestor_key = str(ancestor)
            child_dirs.setdefault(ancestor_key, set()).add(str(child))

    return {
        "dir_counts": dir_counts,
        "child_dirs": {parent: sorted(children) for parent, children in child_dirs.items()},
    }


def _all_tracked_dirs(
    dir_counts: Counter[str],
    child_dirs: dict[str, set[str]],
) -> set[str]:
    all_dirs: set[str] = set(dir_counts.keys())
    all_dirs.update(child_dirs.keys())
    for children in child_dirs.values():
        all_dirs.update(children)
    return all_dirs


def _is_overloaded(
    *,
    file_count: int,
    direct_child_count: int,
    combined_score: int,
    settings: FlatDirDetectionConfig,
) -> bool:
    return (
        file_count >= settings.threshold
        or direct_child_count >= settings.child_dir_threshold
        or combined_score >= settings.combined_threshold
    )


def _fragmentation_entry(
    *,
    dir_path: str,
    file_count: int,
    direct_children: set[str],
    direct_child_count: int,
    combined_score: int,
    settings: FlatDirDetectionConfig,
    dir_counts: Counter[str],
    child_dirs: dict[str, set[str]],
) -> dict | None:
    sparse_child_count = 0
    for child in direct_children:
        child_file_count = int(dir_counts.get(child, 0))
        child_child_count = len(child_dirs.get(child, set()))
        if (
            child_file_count <= settings.sparse_child_file_threshold
            and child_child_count == 0
        ):
            sparse_child_count += 1
    sparse_child_ratio = (
        float(sparse_child_count) / float(direct_child_count)
        if direct_child_count
        else 0.0
    )
    fragmented = (
        direct_child_count >= settings.sparse_parent_child_threshold
        and sparse_child_count >= settings.sparse_child_count_threshold
        and sparse_child_ratio >= settings.sparse_child_ratio_threshold
    )
    if not fragmented:
        return None
    return {
        "directory": dir_path,
        "file_count": file_count,
        "child_dir_count": direct_child_count,
        "combined_score": combined_score,
        "kind": "fragmented",
        "sparse_child_count": sparse_child_count,
        "sparse_child_ratio": sparse_child_ratio,
        "sparse_child_file_threshold": settings.sparse_child_file_threshold,
    }


def _thin_wrapper_entry(
    *,
    dir_path: str,
    thin_names: set[str],
    file_count: int,
    direct_child_count: int,
    combined_score: int,
    settings: FlatDirDetectionConfig,
    child_dirs: dict[str, set[str]],
) -> dict | None:
    dir_name = Path(dir_path).name.lower()
    parent_key = str(Path(dir_path).parent)
    parent_sibling_count = len(child_dirs.get(parent_key, set()))
    wrapper_item_count = file_count + direct_child_count
    thin_wrapper = (
        dir_name in thin_names
        and wrapper_item_count == 1
        and file_count <= settings.thin_wrapper_max_file_count
        and direct_child_count <= settings.thin_wrapper_max_child_dir_count
        and parent_sibling_count >= settings.thin_wrapper_parent_sibling_threshold
    )
    if not thin_wrapper:
        return None
    return {
        "directory": dir_path,
        "file_count": file_count,
        "child_dir_count": direct_child_count,
        "combined_score": combined_score,
        "kind": "thin_wrapper",
        "parent_sibling_count": parent_sibling_count,
        "wrapper_item_count": wrapper_item_count,
    }


def _sort_entries(entries: list[dict]) -> list[dict]:
    return sorted(
        entries,
        key=lambda entry: (
            -int(entry["combined_score"]),
            -int(entry.get("parent_sibling_count", 0)),
            -int(entry.get("sparse_child_count", 0)),
            -int(entry["child_dir_count"]),
            -int(entry["file_count"]),
        ),
    )


def detect_flat_dirs(
    path: Path,
    file_finder,
    threshold: int = 20,
    *,
    config: FlatDirDetectionConfig | None = None,
    child_dir_threshold: int = 10,
    child_dir_weight: int = 3,
    combined_threshold: int = 30,
    sparse_parent_child_threshold: int = 8,
    sparse_child_file_threshold: int = 1,
    sparse_child_count_threshold: int = 6,
    sparse_child_ratio_threshold: float = 0.7,
    thin_wrapper_parent_sibling_threshold: int = 10,
    thin_wrapper_max_file_count: int = 1,
    thin_wrapper_max_child_dir_count: int = 1,
    thin_wrapper_names: tuple[str, ...] = (
        "components",
        "hooks",
        "utils",
        "services",
        "state",
        "contexts",
        "contracts",
        "types",
        "models",
        "adapters",
        "helpers",
        "core",
        "common",
    ),
) -> tuple[list[dict], int]:
    """Find overloaded/fragmented directories using count and fan-out heuristics."""
    settings = _resolve_detection_settings(
        threshold=threshold,
        config=config,
        child_dir_threshold=child_dir_threshold,
        child_dir_weight=child_dir_weight,
        combined_threshold=combined_threshold,
        sparse_parent_child_threshold=sparse_parent_child_threshold,
        sparse_child_file_threshold=sparse_child_file_threshold,
        sparse_child_count_threshold=sparse_child_count_threshold,
        sparse_child_ratio_threshold=sparse_child_ratio_threshold,
        thin_wrapper_parent_sibling_threshold=thin_wrapper_parent_sibling_threshold,
        thin_wrapper_max_file_count=thin_wrapper_max_file_count,
        thin_wrapper_max_child_dir_count=thin_wrapper_max_child_dir_count,
        thin_wrapper_names=thin_wrapper_names,
    )
    files = file_finder(path)
    scan_root = path.resolve()
    dir_counts, child_dirs = _build_dir_stats(scan_root, files)
    all_dirs = _all_tracked_dirs(dir_counts, child_dirs)

    thin_names = {name.lower() for name in settings.thin_wrapper_names}
    if not thin_names:
        thin_names = set(THIN_WRAPPER_NAMES)

    entries: list[dict] = []
    for dir_path in sorted(all_dirs):
        file_count = int(dir_counts.get(dir_path, 0))
        direct_children = child_dirs.get(dir_path, set())
        direct_child_count = len(direct_children)
        combined_score = file_count + (settings.child_dir_weight * direct_child_count)
        has_local_files = dir_path in dir_counts

        if has_local_files:
            if _is_overloaded(
                file_count=file_count,
                direct_child_count=direct_child_count,
                combined_score=combined_score,
                settings=settings,
            ):
                entries.append(
                    {
                        "directory": dir_path,
                        "file_count": file_count,
                        "child_dir_count": direct_child_count,
                        "combined_score": combined_score,
                        "kind": "overload",
                    }
                )
                continue
            fragmented_entry = _fragmentation_entry(
                dir_path=dir_path,
                file_count=file_count,
                direct_children=direct_children,
                direct_child_count=direct_child_count,
                combined_score=combined_score,
                settings=settings,
                dir_counts=dir_counts,
                child_dirs=child_dirs,
            )
            if fragmented_entry is not None:
                entries.append(fragmented_entry)
                continue

        thin_wrapper = _thin_wrapper_entry(
            dir_path=dir_path,
            thin_names=thin_names,
            file_count=file_count,
            direct_child_count=direct_child_count,
            combined_score=combined_score,
            settings=settings,
            child_dirs=child_dirs,
        )
        if thin_wrapper is not None:
            entries.append(thin_wrapper)
    return _sort_entries(entries), len(all_dirs)
