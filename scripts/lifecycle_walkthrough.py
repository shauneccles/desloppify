#!/usr/bin/env python3
"""Interactive lifecycle walkthrough — spoof state at each stage so you can
run desloppify commands (next, plan, status) as a real agent would see them.

Usage:
    python scripts/lifecycle_walkthrough.py

At each stage the script writes state + plan files, then pauses.
You open another terminal, cd to the printed temp dir, and run commands like:

    DESLOPPIFY_ROOT=<tmpdir> python -m desloppify --lang python next
    DESLOPPIFY_ROOT=<tmpdir> python -m desloppify --lang python plan
    DESLOPPIFY_ROOT=<tmpdir> python -m desloppify --lang python status

Press Enter to advance to the next lifecycle stage.
"""

from __future__ import annotations

import os
import orjson
import sys
import tempfile
from pathlib import Path

# Ensure desloppify is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from desloppify.base.subjective_dimensions import DISPLAY_NAMES
from desloppify.engine._plan.operations_lifecycle import purge_ids
from desloppify.engine._plan.schema import empty_plan
from desloppify.engine._plan.stale_dimensions import (
    TRIAGE_STAGE_IDS,
    WORKFLOW_COMMUNICATE_SCORE_ID,
    WORKFLOW_CREATE_PLAN_ID,
    sync_communicate_score_needed,
    sync_create_plan_needed,
    sync_triage_needed,
    sync_unscored_dimensions,
)
from desloppify.engine._state.schema import empty_state, utc_now

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DIM_KEYS = ("naming_quality", "logic_clarity", "type_safety")
DIM_DISPLAY = {k: DISPLAY_NAMES[k] for k in DIM_KEYS}

OBJECTIVE_ISSUES = {
    "complexity::src/app.py::deep_nesting": {
        "id": "complexity::src/app.py::deep_nesting",
        "detector": "complexity",
        "file": "src/app.py",
        "tier": 2,
        "confidence": "high",
        "summary": "Deeply nested conditionals in process_order()",
        "detail": {"max_depth": 6},
        "status": "open",
        "first_seen": utc_now(),
        "last_seen": utc_now(),
        "resolved_at": None,
        "reopen_count": 0,
    },
    "naming::src/util.py::bad_name": {
        "id": "naming::src/util.py::bad_name",
        "detector": "naming",
        "file": "src/util.py",
        "tier": 3,
        "confidence": "medium",
        "summary": "Non-descriptive function name: do_stuff()",
        "detail": {},
        "status": "open",
        "first_seen": utc_now(),
        "last_seen": utc_now(),
        "resolved_at": None,
        "reopen_count": 0,
    },
    "unused::src/helpers.py::dead_import": {
        "id": "unused::src/helpers.py::dead_import",
        "detector": "unused",
        "file": "src/helpers.py",
        "tier": 1,
        "confidence": "high",
        "summary": "Unused import: os.path",
        "detail": {},
        "status": "open",
        "first_seen": utc_now(),
        "last_seen": utc_now(),
        "resolved_at": None,
        "reopen_count": 0,
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _placeholder_dim(key: str) -> tuple[dict, dict]:
    """Return (dim_scores_entry, subjective_assessment) for a placeholder."""
    return (
        {
            "score": 0, "strict": 0, "failing": 0, "checks": 0,
            "detectors": {"subjective_assessment": {"placeholder": True, "dimension_key": key}},
        },
        {"score": 0, "placeholder": True},
    )


def _scored_dim(key: str, score: float) -> tuple[dict, dict]:
    """Return (dim_scores_entry, subjective_assessment) with a real score."""
    return (
        {
            "score": score, "strict": score, "failing": 0, "checks": 1,
            "detectors": {"subjective_assessment": {"placeholder": False, "dimension_key": key}},
        },
        {"score": score, "placeholder": False},
    )


def _apply_dims(state: dict, dims: dict[str, tuple[dict, dict]]) -> None:
    """Write dimension data into state."""
    for key, (dim_entry, assessment) in dims.items():
        state["dimension_scores"][DIM_DISPLAY[key]] = dim_entry
        state["subjective_assessments"][key] = assessment


def _save(state: dict, plan: dict, state_dir: Path) -> None:
    """Write state + plan to disk."""
    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / "state-python.json"
    plan_path = state_dir / "plan.json"
    state_path.write_text(
        orjson.dumps(state, option=orjson.OPT_INDENT_2, default=str).decode("utf-8")
    )
    plan_path.write_text(
        orjson.dumps(plan, option=orjson.OPT_INDENT_2, default=str).decode("utf-8")
    )


def _pause(tmpdir: Path, stage: str, description: str) -> None:
    """Print instructions and wait for user input."""
    print()
    print(f"{'=' * 60}")
    print(f"  STAGE: {stage}")
    print(f"{'=' * 60}")
    print(f"  {description}")
    print()
    print(f"  In another terminal, try:")
    print(f"    DESLOPPIFY_ROOT={tmpdir} python -m desloppify --lang python next")
    print(f"    DESLOPPIFY_ROOT={tmpdir} python -m desloppify --lang python plan")
    print(f"    DESLOPPIFY_ROOT={tmpdir} python -m desloppify --lang python status")
    print()
    input("  Press Enter to advance to next stage...")


# ---------------------------------------------------------------------------
# Main walkthrough
# ---------------------------------------------------------------------------

def main() -> None:
    tmpdir = Path(tempfile.mkdtemp(prefix="desloppify-lifecycle-"))
    state_dir = tmpdir / ".desloppify"

    # Create minimal source files so scan_path resolves
    src = tmpdir / "src"
    src.mkdir()
    (src / "app.py").write_text("def process_order(): pass\n")
    (src / "util.py").write_text("def do_stuff(): pass\n")
    (src / "helpers.py").write_text("import os.path\n")

    # Initialize git so get_project_root() works
    os.system(f"git init -q {tmpdir}")

    print(f"\n  Lifecycle walkthrough sandbox: {tmpdir}")
    print(f"  State dir: {state_dir}")

    # --- Build base state ---
    state = empty_state()
    state["lang"] = "python"
    state["scan_path"] = "src"
    state["scan_count"] = 1
    state["last_scan"] = utc_now()
    state["issues"] = dict(OBJECTIVE_ISSUES)
    state.setdefault("dimension_scores", {})
    state.setdefault("subjective_assessments", {})

    plan = empty_plan()

    # ══════════════════════════════════════════════════════════════
    # Stage 1: Fresh scan — placeholder dimensions (initial reviews)
    # ══════════════════════════════════════════════════════════════
    _apply_dims(state, {k: _placeholder_dim(k) for k in DIM_KEYS})
    sync_unscored_dimensions(plan, state)
    _save(state, plan, state_dir)

    _pause(tmpdir, "1 — Initial Reviews",
           "Fresh scan. 3 subjective dimensions need initial review.\n"
           "  `next` should show only subjective review items.\n"
           "  Objective issues are hidden until reviews are done.")

    # ══════════════════════════════════════════════════════════════
    # Stage 2: Reviews completed — objectives unlock
    # ══════════════════════════════════════════════════════════════
    _apply_dims(state, {k: _scored_dim(k, 72.0) for k in DIM_KEYS})
    subj_ids = [fid for fid in plan["queue_order"] if fid.startswith("subjective::")]
    purge_ids(plan, subj_ids)
    state["strict_score"] = 72.0
    state["overall_score"] = 72.0
    state["objective_score"] = 80.0
    _save(state, plan, state_dir)

    _pause(tmpdir, "2 — Reviews Complete (between scans)",
           "All 3 reviews done (scored at 72). Subjective IDs purged from plan.\n"
           "  `next` should now show objective issues.\n"
           "  No workflow items yet — hasn't been scanned since reviews.")

    # ══════════════════════════════════════════════════════════════
    # Stage 3: Next scan — communicate-score + create-plan injected
    # ══════════════════════════════════════════════════════════════
    state["scan_count"] = 2
    state["last_scan"] = utc_now()
    sync_communicate_score_needed(plan, state)
    sync_create_plan_needed(plan, state)
    _save(state, plan, state_dir)

    _pause(tmpdir, "3 — Post-scan: Workflow Items Injected",
           "Simulated a second scan. Reconcile injected:\n"
           "  - workflow::communicate-score (show your scores)\n"
           "  - workflow::create-plan (organize your backlog)\n"
           "  `next` should show communicate-score first.")

    # ══════════════════════════════════════════════════════════════
    # Stage 4: Workflow items completed — pure objective work
    # ══════════════════════════════════════════════════════════════
    purge_ids(plan, [WORKFLOW_COMMUNICATE_SCORE_ID, WORKFLOW_CREATE_PLAN_ID])
    _save(state, plan, state_dir)

    _pause(tmpdir, "4 — Workflow Complete: Objective Work",
           "communicate-score and create-plan resolved.\n"
           "  `next` should show the highest-impact objective issue.\n"
           "  `plan` should show the full backlog.")

    # ══════════════════════════════════════════════════════════════
    # Stage 5: Review issues appear → triage stages
    # ══════════════════════════════════════════════════════════════
    review_issues = {
        "review::src/app.py::naming-concern": {
            "id": "review::src/app.py::naming-concern",
            "detector": "review",
            "file": "src/app.py",
            "tier": 2,
            "confidence": "high",
            "summary": "Naming quality: function names in src/app.py don't follow conventions",
            "detail": {"dimension": "naming_quality"},
            "status": "open",
            "first_seen": utc_now(),
            "last_seen": utc_now(),
            "resolved_at": None,
            "reopen_count": 0,
        },
        "review::src/util.py::logic-concern": {
            "id": "review::src/util.py::logic-concern",
            "detector": "review",
            "file": "src/util.py",
            "tier": 2,
            "confidence": "high",
            "summary": "Logic clarity: complex branching in src/util.py needs simplification",
            "detail": {"dimension": "logic_clarity"},
            "status": "open",
            "first_seen": utc_now(),
            "last_seen": utc_now(),
            "resolved_at": None,
            "reopen_count": 0,
        },
    }
    state["issues"].update(review_issues)
    state["scan_count"] = 3
    state["last_scan"] = utc_now()
    sync_triage_needed(plan, state)
    _save(state, plan, state_dir)

    _pause(tmpdir, "5 — Review Issues: Triage Needed",
           "New review issues surfaced from subjective analysis.\n"
           "  Triage stages injected (observe → reflect → organize → commit).\n"
           "  `next` should show triage stages before objective work.")

    # ══════════════════════════════════════════════════════════════
    # Stage 6: Triage complete → back to objectives
    # ══════════════════════════════════════════════════════════════
    purge_ids(plan, list(TRIAGE_STAGE_IDS))
    _save(state, plan, state_dir)

    _pause(tmpdir, "6 — Triage Complete: Back to Work",
           "All triage stages resolved. Back to objective work.\n"
           "  `next` should show objective + review issues ranked by impact.\n"
           "  This is the steady-state work phase.")

    print()
    print(f"  Walkthrough complete! Sandbox at: {tmpdir}")
    print(f"  Clean up with: rm -rf {tmpdir}")
    print()


if __name__ == "__main__":
    main()
