"""Core query payload writing helpers."""

from __future__ import annotations

import orjson
import logging
import sys
from pathlib import Path

from desloppify.core.config import config_for_query, load_config
from desloppify.core.file_paths import safe_write_text
from desloppify.core.output_contract import OutputResult
from desloppify.state import json_default

logger = logging.getLogger(__name__)


def write_query(data: dict, *, query_file: Path) -> OutputResult:
    """Write structured query payloads with config context and graceful fallback."""
    if "config" not in data:
        try:
            data["config"] = config_for_query(load_config())
        except (OSError, ValueError, orjson.JSONDecodeError) as exc:
            data["config_error"] = str(exc)
            logger.debug("Skipping config injection into query payload: %s", exc)
    try:
        safe_write_text(
            query_file, orjson.dumps(data, option=orjson.OPT_INDENT_2, default=json_default).decode("utf-8") + "\n"
        )
        print("  → query.json updated", file=sys.stderr)
        return OutputResult(
            ok=True,
            status="written",
            message=f"query payload written to {query_file}",
        )
    except OSError as exc:
        data["query_write_error"] = str(exc)
        print(f"  ⚠ Could not write query.json: {exc}", file=sys.stderr)
        return OutputResult(
            ok=False,
            status="error",
            message=str(exc),
            error_kind="query_write_error",
        )


__all__ = ["write_query"]
