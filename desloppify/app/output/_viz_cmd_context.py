"""CLI context loading helpers for `desloppify tree` and `desloppify viz`."""

from __future__ import annotations

import orjson
from pathlib import Path

from desloppify import state as state_module
from desloppify.app.commands.helpers.lang import resolve_lang
from desloppify.app.commands.helpers.runtime import command_runtime
from desloppify.base.output.fallbacks import warn_best_effort


def load_cmd_context(args: object) -> tuple[Path, object | None, dict | None]:
    """Load language config and state from CLI args."""
    lang = resolve_lang(args)
    runtime = command_runtime(args)
    state = runtime.state
    if not isinstance(state, dict):
        scan_state_path = runtime.state_path
        try:
            state = state_module.load_state(scan_state_path)
        except (OSError, orjson.JSONDecodeError) as exc:
            warn_best_effort(
                "Could not load scan state for visualization "
                f"({scan_state_path}, {exc.__class__.__name__}: {exc}); "
                "rendering without issue overlays."
            )
            state = None
    return Path(args.path), lang, state


__all__ = ["load_cmd_context"]
