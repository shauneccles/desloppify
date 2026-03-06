"""Language-resolution helpers for command modules."""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from desloppify import languages as lang_api
from desloppify.base.discovery.paths import get_project_root

if TYPE_CHECKING:
    from desloppify.languages._framework.base.types import LangConfig


logger = logging.getLogger(__name__)


class LangResolutionError(SystemExit):
    """Raised when language resolution fails with a user-facing message.

    Inherits from SystemExit so that callers which don't catch it explicitly
    will still terminate with a non-zero exit code, matching the previous
    sys.exit(1) behaviour.  The CLI top-level catches it to print a clean
    error without a traceback.
    """

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(1)


EXTRA_ROOT_MARKERS = (
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "go.mod",
    "Cargo.toml",
)


def _cache_once(fn: Callable[[], tuple[str, ...]]) -> Callable[[], tuple[str, ...]]:
    """Cache a zero-arg function once while preserving cache_clear for tests."""
    cached = lru_cache(maxsize=1)(fn)
    return cached


@_cache_once
def _lang_config_markers() -> tuple[str, ...]:
    """Collect project-root marker files from language plugins + fallback markers."""
    markers = set(EXTRA_ROOT_MARKERS)

    for lang_name in lang_api.available_langs():
        try:
            cfg = lang_api.get_lang(lang_name)
        except (ImportError, ValueError, TypeError, AttributeError) as exc:
            logger.debug(
                "Skipping language marker collection for %s: %s", lang_name, exc
            )
            continue
        for marker in getattr(cfg, "detect_markers", []) or []:
            if not isinstance(marker, str):
                continue
            cleaned = marker.strip()
            if cleaned:
                markers.add(cleaned)
    return tuple(sorted(markers))


def resolve_detection_root(
    args: object,
    *,
    project_root: Path | None = None,
    marker_provider: Callable[[], tuple[str, ...]] | None = None,
) -> Path:
    """Best root to auto-detect language from."""
    project_root = project_root or get_project_root()
    marker_provider = marker_provider or _lang_config_markers
    markers = marker_provider()
    root = project_root if project_root is not None else get_project_root()

    raw_path = getattr(args, "path", None)
    if not raw_path:
        return root

    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    search_root = candidate if candidate.is_dir() else candidate.parent

    roots_to_check: list[Path] = [search_root]
    try:
        search_root.relative_to(project_root)
        parent = search_root.parent
        while parent != parent.parent:
            roots_to_check.append(parent)
            if parent == project_root:
                break
            parent = parent.parent
    except ValueError:
        if search_root.parent != search_root:
            roots_to_check.append(search_root.parent)

    for root in roots_to_check:
        if any((root / marker).exists() for marker in markers):
            return root
    return search_root


def auto_detect_lang_name(args: object) -> str | None:
    """Auto-detect language using the most relevant root for this command."""
    root = resolve_detection_root(args)
    detected = lang_api.auto_detect_lang(root)
    if detected is None and root != get_project_root():
        detected = lang_api.auto_detect_lang(get_project_root())
    return detected


def resolve_lang(args: object) -> LangConfig | None:
    """Resolve language config from args, with auto-detection fallback."""
    lang_name = getattr(args, "lang", None)
    if lang_name is None:
        lang_name = auto_detect_lang_name(args)
    if lang_name is None:
        return None
    try:
        return lang_api.get_lang(lang_name)
    except ValueError as exc:
        langs = lang_api.available_langs()
        langs_str = ", ".join(langs) if langs else "registered language plugins"
        raise LangResolutionError(
            f"{exc}\n  Hint: use --lang to select manually (available: {langs_str})"
        ) from exc


def resolve_lang_settings(config: dict, lang: LangConfig) -> dict[str, object]:
    """Resolve persisted per-language settings from config.languages.<lang>."""
    if not isinstance(config, dict):
        return lang.normalize_settings({})
    languages = config.get("languages", {})
    if not isinstance(languages, dict):
        return lang.normalize_settings({})
    raw = languages.get(lang.name, {})
    return lang.normalize_settings(raw if isinstance(raw, dict) else {})
